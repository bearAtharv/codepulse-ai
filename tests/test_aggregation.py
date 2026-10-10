"""Tests for Phase 5 finding aggregation, deduplication, and GitHub review posting."""

from __future__ import annotations

import pytest

from codepulse.aggregation.comments import (
    SEVERITY_BADGES,
    format_finding_comment,
)
from codepulse.aggregation.dedup import (
    MAX_REVIEW_COMMENTS,
    deduplicate_and_sort,
)
from codepulse.aggregation.engine import (
    aggregate_and_post,
    check_tier2_escalation,
    persist_findings_stub,
)
from codepulse.aggregation.github_poster import (
    GitHubReviewPayload,
    MockGitHubPoster,
    ReviewCommentPayload,
    get_github_poster,
)
from codepulse.aggregation.line_mapping import (
    map_findings_to_diff_positions,
    parse_unified_diff,
)
from codepulse.aggregation.models import (
    Finding,
    RepoContext,
)
from codepulse.aggregation.summary import compose_review_summary
from codepulse.analysis.heuristics.base import ASTFinding
from codepulse.analysis.llm_schemas import (
    Confidence,
    LLMFindingItem,
    Severity,
)

SAMPLE_DIFF = """--- a/src/app.py
+++ b/src/app.py
@@ -10,6 +10,8 @@ def run():
     config = load_config()
-    data = raw_eval(input_data)
+    data = safe_eval(input_data)
+    result = execute_query(f"SELECT * FROM users WHERE id = {data}")
     return result
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,4 +1,5 @@
 import os
+import pickle
 def helper():
     pass
"""


# ── 1. Model Adapters ──────────────────────────────────────────────────


def test_finding_adapter_from_ast():
    ast_f = ASTFinding(
        rule_id="py_pickle_load",
        category="A08",
        severity="critical",
        confidence="high",
        title="Insecure Deserialization via pickle.load",
        explanation="pickle.load can execute arbitrary bytecode.",
        remediation="Use json or safe serialization.",
        file_path="src/utils.py",
        line_start=2,
        line_end=2,
    )

    f = Finding.from_ast_finding(ast_f)
    assert f.file_path == "src/utils.py"
    assert f.line_start == 2
    assert f.line_end == 2
    assert f.severity == "critical"
    assert f.category == "A08"
    assert f.confidence == "high"
    assert f.source == "ast"
    assert f.suggested_fix is None


def test_finding_adapter_from_llm():
    llm_f = LLMFindingItem(
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        severity=Severity.critical,
        category="A03",
        title="SQL Injection",
        explanation="Untrusted input formatted directly into SQL query.",
        remediation="Use parameterized queries.",
        confidence=Confidence.high,
    )

    f = Finding.from_llm_finding(llm_f)
    assert f.file_path == "src/app.py"
    assert f.line_start == 12
    assert f.severity == "critical"
    assert f.category == "A03"
    assert f.confidence == "high"
    assert f.source == "llm"
    assert f.suggested_fix is None


# ── 2. Deduplication and Collision Merging ──────────────────────────────


def test_dedup_no_collision_preserves_both():
    f1 = Finding(
        file_path="a.py",
        line_start=10,
        line_end=10,
        severity="high",
        category="A03",
        title="SQL Injection",
        explanation="AST found SQLi",
        remediation="Parametrize",
        confidence="high",
        source="ast",
    )
    f2 = Finding(
        file_path="b.py",
        line_start=20,
        line_end=20,
        severity="critical",
        category="A08",
        title="Insecure Deserialization",
        explanation="LLM found pickle",
        remediation="Use json",
        confidence="high",
        source="llm",
    )

    res = deduplicate_and_sort([f1, f2])
    assert res.total_raw == 2
    assert res.merged_count == 0
    assert len(res.findings) == 2
    # Critical should be sorted before high
    assert res.findings[0].severity == "critical"
    assert res.findings[1].severity == "high"


def test_dedup_collision_higher_confidence_wins_and_attributes_loser():
    # AST with high confidence
    ast_f = Finding(
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        severity="critical",
        category="A03",
        title="SQL Injection",
        explanation="Direct variable interpolation in SQL string.",
        remediation="Use parameterized query.",
        confidence="high",
        source="ast",
    )
    # LLM with medium confidence on same (file, line, category, title)
    llm_f = Finding(
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        severity="critical",
        category="A03",
        title="SQL Injection",
        explanation="Potential SQL injection detected via LLM.",
        remediation="Use prepared statements.",
        confidence="medium",
        source="llm",
    )

    res = deduplicate_and_sort([ast_f, llm_f])
    assert res.total_raw == 2
    assert res.merged_count == 1
    assert len(res.findings) == 1

    merged = res.findings[0]
    assert merged.confidence == "high"
    assert merged.source == "merged"
    assert "Direct variable interpolation" in merged.explanation
    assert "Also detected by llm." in merged.explanation


def test_dedup_collision_llm_higher_confidence_wins():
    ast_f = Finding(
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        severity="high",
        category="A03",
        title="SQL Injection",
        explanation="AST detected SQL pattern.",
        remediation="Fix it.",
        confidence="low",
        source="ast",
    )
    llm_f = Finding(
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        severity="critical",
        category="A03",
        title="SQL Injection",
        explanation="LLM verified high impact SQL injection exploit.",
        remediation="Use bound parameters.",
        confidence="high",
        source="llm",
        suggested_fix="execute_query(sql, (param,))",
    )

    res = deduplicate_and_sort([ast_f, llm_f])
    assert res.merged_count == 1
    merged = res.findings[0]
    assert merged.severity == "critical"
    assert merged.confidence == "high"
    assert merged.source == "merged"
    assert "LLM verified high impact" in merged.explanation
    assert "Also detected by ast." in merged.explanation
    assert merged.suggested_fix == "execute_query(sql, (param,))"


# ── 3. Sorting Order ───────────────────────────────────────────────────


def test_sorting_order_severity_file_line():
    findings = [
        Finding(
            file_path="b.py",
            line_start=10,
            line_end=10,
            severity="low",
            category="A05",
            title="T1",
            explanation="e",
            remediation="r",
            confidence="high",
            source="ast",
        ),
        Finding(
            file_path="a.py",
            line_start=50,
            line_end=50,
            severity="critical",
            category="A03",
            title="T2",
            explanation="e",
            remediation="r",
            confidence="high",
            source="llm",
        ),
        Finding(
            file_path="a.py",
            line_start=10,
            line_end=10,
            severity="critical",
            category="A03",
            title="T3",
            explanation="e",
            remediation="r",
            confidence="high",
            source="llm",
        ),
        Finding(
            file_path="a.py",
            line_start=20,
            line_end=20,
            severity="medium",
            category="A01",
            title="T4",
            explanation="e",
            remediation="r",
            confidence="high",
            source="ast",
        ),
    ]

    res = deduplicate_and_sort(findings)
    # Expected order:
    # 1. critical a.py:10
    # 2. critical a.py:50
    # 3. medium a.py:20
    # 4. low b.py:10
    assert [f.title for f in res.findings] == ["T3", "T2", "T4", "T1"]


# ── 4. Crucial Cap Invariant: Critical Findings Never Dropped ───────────


def test_truncation_cap_never_drops_critical_findings():
    """Verify that when findings exceed the cap, critical findings are NEVER dropped."""
    findings: list[Finding] = []

    # 10 critical findings
    for i in range(10):
        findings.append(
            Finding(
                file_path=f"src/crit_{i}.py",
                line_start=i + 1,
                line_end=i + 1,
                severity="critical",
                category="A03",
                title=f"Critical Vuln {i}",
                explanation="expl",
                remediation="rem",
                confidence="high",
                source="ast",
            )
        )

    # 100 high findings
    for i in range(100):
        findings.append(
            Finding(
                file_path=f"src/high_{i}.py",
                line_start=i + 1,
                line_end=i + 1,
                severity="high",
                category="A01",
                title=f"High Vuln {i}",
                explanation="expl",
                remediation="rem",
                confidence="high",
                source="llm",
            )
        )

    # 180 medium findings (Total = 290 > 256)
    for i in range(180):
        findings.append(
            Finding(
                file_path=f"src/med_{i}.py",
                line_start=i + 1,
                line_end=i + 1,
                severity="medium",
                category="A05",
                title=f"Medium Vuln {i}",
                explanation="expl",
                remediation="rem",
                confidence="medium",
                source="llm",
            )
        )

    assert len(findings) == 290
    res = deduplicate_and_sort(findings, max_findings=MAX_REVIEW_COMMENTS)

    assert len(res.findings) == 256
    assert res.truncated_count == 34
    assert len(res.dropped_findings) == 34

    # CRITICAL INVARIANT: 0 dropped findings are critical
    dropped_criticals = [d for d in res.dropped_findings if d.severity.lower() == "critical"]
    assert len(dropped_criticals) == 0, f"Found {len(dropped_criticals)} critical findings in dropped list!"

    # All 10 critical findings must be retained in res.findings
    kept_criticals = [k for k in res.findings if k.severity.lower() == "critical"]
    assert len(kept_criticals) == 10


def test_custom_cap_truncation_rebalance():
    """Verify small custom cap (e.g. 5) correctly preserves critical findings."""
    findings = [
        Finding(
            file_path="a.py",
            line_start=i,
            line_end=i,
            severity="medium",
            category="A05",
            title=f"Med {i}",
            explanation="e",
            remediation="r",
            confidence="high",
            source="ast",
        )
        for i in range(10)
    ]
    # Add 2 critical findings
    findings.append(
        Finding(
            file_path="crit1.py",
            line_start=1,
            line_end=1,
            severity="critical",
            category="A03",
            title="Crit 1",
            explanation="e",
            remediation="r",
            confidence="high",
            source="ast",
        )
    )
    findings.append(
        Finding(
            file_path="crit2.py",
            line_start=2,
            line_end=2,
            severity="critical",
            category="A03",
            title="Crit 2",
            explanation="e",
            remediation="r",
            confidence="high",
            source="ast",
        )
    )

    res = deduplicate_and_sort(findings, max_findings=5)
    assert len(res.findings) == 5
    assert res.truncated_count == 7
    # Dropped must contain 0 criticals
    assert all(d.severity != "critical" for d in res.dropped_findings)
    # Kept must contain both criticals
    assert sum(1 for k in res.findings if k.severity == "critical") == 2


# ── 5. Diff Parsing and Line Mapping ───────────────────────────────────


def test_parse_unified_diff():
    diffs = parse_unified_diff(SAMPLE_DIFF)
    assert "src/app.py" in diffs
    assert "src/utils.py" in diffs

    app_diff = diffs["src/app.py"]
    assert len(app_diff.hunks) == 1
    hunk = app_diff.hunks[0]
    assert hunk.new_start == 10
    # Modified lines in src/app.py are 11 and 12 (+ safe_eval, + result = execute_query)
    assert 11 in hunk.modified_lines
    assert 12 in hunk.modified_lines
    # Context lines are 10 (def run():) and 13 (return result)
    assert 10 in hunk.context_lines
    assert 13 in hunk.context_lines


def test_map_finding_to_modified_line():
    finding = Finding(
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        severity="critical",
        category="A03",
        title="SQL Injection",
        explanation="SQLi on line 12",
        remediation="Parametrize",
        confidence="high",
        source="ast",
    )

    mapped = map_findings_to_diff_positions([finding], SAMPLE_DIFF)
    f = mapped[0]
    assert f.is_in_diff is True
    assert f.diff_line == 12
    assert f.diff_side == "RIGHT"
    assert f.diff_start_line is None


def test_map_multi_line_finding_sets_start_line():
    finding = Finding(
        file_path="src/app.py",
        line_start=11,
        line_end=12,
        severity="high",
        category="A03",
        title="Multi-line SQL",
        explanation="Multi-line issue",
        remediation="Fix it",
        confidence="high",
        source="llm",
    )

    mapped = map_findings_to_diff_positions([finding], SAMPLE_DIFF)
    f = mapped[0]
    assert f.is_in_diff is True
    assert f.diff_line == 12
    assert f.diff_start_line == 11
    assert f.diff_side == "RIGHT"


def test_map_finding_on_context_line_remaps_to_nearest_modified():
    finding = Finding(
        file_path="src/app.py",
        line_start=10,
        line_end=10,  # line 10 is 'def run():' (context line)
        severity="low",
        category="A05",
        title="Context Line Issue",
        explanation="Function declaration flag",
        remediation="Check signature",
        confidence="medium",
        source="ast",
    )

    mapped = map_findings_to_diff_positions([finding], SAMPLE_DIFF)
    f = mapped[0]
    assert f.is_in_diff is True
    # Nearest modified line is 11
    assert f.diff_line == 11
    assert "placed on nearest changed line 11" in f.explanation


def test_map_finding_outside_diff_marks_not_in_diff():
    finding = Finding(
        file_path="src/app.py",
        line_start=99,
        line_end=99,
        severity="medium",
        category="A01",
        title="Out of Hunk",
        explanation="Far away",
        remediation="Check auth",
        confidence="high",
        source="llm",
    )

    mapped = map_findings_to_diff_positions([finding], SAMPLE_DIFF)
    f = mapped[0]
    assert f.is_in_diff is False
    assert f.diff_line is None


def test_map_finding_file_not_in_diff():
    finding = Finding(
        file_path="src/nonexistent.py",
        line_start=1,
        line_end=1,
        severity="low",
        category="A05",
        title="Missing File",
        explanation="Not in diff",
        remediation="None",
        confidence="low",
        source="ast",
    )

    mapped = map_findings_to_diff_positions([finding], SAMPLE_DIFF)
    f = mapped[0]
    assert f.is_in_diff is False
    assert f.diff_line is None


# ── 6. Comment Formatting ──────────────────────────────────────────────


def test_format_finding_comment_with_suggested_fix():
    finding = Finding(
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        severity="critical",
        category="A03",
        title="SQL Injection",
        explanation="Direct string formatting in SQL query.",
        remediation="Use parameterized queries.",
        confidence="high",
        source="llm",
        suggested_fix="result = execute_query(sql, (data,))",
    )

    body = format_finding_comment(finding)
    assert "🔴 **Critical**" in body
    assert "`A03` — **SQL Injection**" in body
    assert "```suggestion" in body
    assert "result = execute_query(sql, (data,))" in body
    assert "*Confidence:* High | *Source:* LLM" in body


def test_format_finding_comment_with_remediation_only():
    finding = Finding(
        file_path="src/utils.py",
        line_start=2,
        line_end=2,
        severity="high",
        category="A08",
        title="Insecure Deserialization",
        explanation="pickle.load detected.",
        remediation="Use json.loads instead.",
        confidence="medium",
        source="merged",
        raw_category="pickle_use",
    )

    body = format_finding_comment(finding)
    assert "🟠 **High**" in body
    assert "**Remediation:** Use json.loads instead." in body
    assert "*Confidence:* Medium | *Source:* MERGED" in body
    assert "*Original Category:* `pickle_use`" in body


# ── 7. Review Summary Composition ──────────────────────────────────────


def test_compose_review_summary_structure():
    f1 = Finding(
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        severity="critical",
        category="A03",
        title="SQL Injection",
        explanation="SQLi",
        remediation="Param",
        confidence="high",
        source="ast",
    )
    dedup = deduplicate_and_sort([f1])
    summary = compose_review_summary(
        dedup_result=dedup,
        files_analyzed=2,
        analysis_duration_ms=1500,
        model_version="gemini-3.7-flash",
    )

    assert "## 🛡️ CodePulse AI Security & Quality Review" in summary
    assert "🔴 **Critical:** 1" in summary
    assert "| **Files Analyzed** | 2 |" in summary
    assert "| **Total Findings** | 1 |" in summary
    assert "| **Categories Detected** | `A03` (1) |" in summary
    assert "<summary>🔬 Methodology & Audit Disclosure</summary>" in summary
    assert "gemini-3.7-flash" in summary


def test_compose_review_summary_truncation_notice_and_unmapped():
    findings = [
        Finding(
            file_path="a.py",
            line_start=i,
            line_end=i,
            severity="medium",
            category="A05",
            title=f"Issue {i}",
            explanation="Explanation",
            remediation="Rem",
            confidence="high",
            source="ast",
        )
        for i in range(5)
    ]
    dedup = deduplicate_and_sort(findings, max_findings=2)

    unmapped = [
        Finding(
            file_path="other.py",
            line_start=99,
            line_end=99,
            severity="low",
            category="A09",
            title="Logging failure",
            explanation="Missing audit logging",
            remediation="Add log",
            confidence="low",
            source="llm",
            is_in_diff=False,
        )
    ]

    summary = compose_review_summary(
        dedup_result=dedup,
        unmapped_findings=unmapped,
    )

    assert "3 lower-severity findings were omitted" in summary
    assert "### 📌 Additional Findings (Outside Changed Lines)" in summary
    assert "Logging failure" in summary


def test_compose_review_summary_clean_pr():
    dedup = deduplicate_and_sort([])
    summary = compose_review_summary(dedup_result=dedup)
    assert "No security vulnerabilities or memory leaks detected" in summary


# ── 8. Mock GitHub Poster & Payload Key Validation ──────────────────────


def test_mock_github_poster_payload_validation():
    poster = MockGitHubPoster()

    valid_payload = {
        "event": "COMMENT",
        "body": "## Review Summary",
        "comments": [
            {
                "path": "src/app.py",
                "line": 12,
                "side": "RIGHT",
                "body": "Comment text",
            }
        ],
    }

    res = poster.post_review(
        owner="octocat",
        repo="hello-world",
        pull_number=42,
        payload=valid_payload,
    )

    assert res["id"] == 123456790
    assert res["state"] == "COMMENT"
    assert "octocat/hello-world/pull/42" in res["html_url"]

    # Validate recorded payload keys per architecture doc and user requirement
    last = poster.last_payload
    assert last is not None
    assert "event" in last
    assert "body" in last
    assert "comments" in last
    assert len(last["comments"]) == 1

    comment = last["comments"][0]
    assert "path" in comment
    assert "line" in comment
    assert "side" in comment
    assert "body" in comment
    assert comment["path"] == "src/app.py"
    assert comment["line"] == 12
    assert comment["side"] == "RIGHT"


@pytest.mark.parametrize(
    "invalid_payload,expected_error",
    [
        ({"body": "Missing event", "comments": []}, "missing required key: 'event'"),
        ({"event": "COMMENT", "comments": []}, "missing required key: 'body'"),
        ({"event": "COMMENT", "body": "Summary"}, "missing required key: 'comments'"),
        (
            {
                "event": "COMMENT",
                "body": "Summary",
                "comments": [{"path": "a.py", "line": 10, "side": "RIGHT"}],  # missing body
            },
            "missing required key: 'body'",
        ),
        (
            {
                "event": "COMMENT",
                "body": "Summary",
                "comments": [{"body": "Text", "line": 10, "side": "RIGHT"}],  # missing path
            },
            "missing required key: 'path'",
        ),
        (
            {
                "event": "COMMENT",
                "body": "Summary",
                "comments": [{"path": "a.py", "body": "Text", "side": "RIGHT"}],  # missing line
            },
            "missing required key: 'line'",
        ),
    ],
)
def test_mock_github_poster_rejects_malformed_payload(invalid_payload, expected_error):
    poster = MockGitHubPoster()
    with pytest.raises(ValueError, match=expected_error):
        poster.post_review(
            owner="octocat",
            repo="hello-world",
            pull_number=1,
            payload=invalid_payload,
        )


def test_get_github_poster_factory():
    mock_poster = get_github_poster(mock_github=True)
    assert isinstance(mock_poster, MockGitHubPoster)


# ── 9. Tier 2 Escalation & Persistence Stubs ───────────────────────────


def test_check_tier2_escalation_triggers_on_low_confidence_critical():
    critical_low = Finding(
        file_path="src/app.py",
        line_start=1,
        line_end=1,
        severity="critical",
        category="A03",
        title="Crit",
        explanation="e",
        remediation="r",
        confidence="low",
        source="llm",
    )
    assert check_tier2_escalation([critical_low]) is True


def test_check_tier2_escalation_triggers_on_medium_confidence_critical():
    critical_med = Finding(
        file_path="src/app.py",
        line_start=1,
        line_end=1,
        severity="critical",
        category="A03",
        title="Crit",
        explanation="e",
        remediation="r",
        confidence="medium",
        source="llm",
    )
    assert check_tier2_escalation([critical_med]) is True


def test_check_tier2_escalation_false_on_high_confidence_critical():
    critical_high = Finding(
        file_path="src/app.py",
        line_start=1,
        line_end=1,
        severity="critical",
        category="A03",
        title="Crit",
        explanation="e",
        remediation="r",
        confidence="high",
        source="llm",
    )
    assert check_tier2_escalation([critical_high]) is False


def test_check_tier2_escalation_false_on_non_critical():
    high_low = Finding(
        file_path="src/app.py",
        line_start=1,
        line_end=1,
        severity="high",
        category="A01",
        title="High",
        explanation="e",
        remediation="r",
        confidence="low",
        source="llm",
    )
    assert check_tier2_escalation([high_low]) is False


def test_persist_findings_stub_executes():
    context = RepoContext(repository_full_name="org/repo", pull_request_number=5)
    # Stub should run without exception
    persist_findings_stub([], 123456789, context)


# ── 10. End-to-End aggregate_and_post() with Mock Poster ────────────────


def test_aggregate_and_post_end_to_end():
    ast_findings = [
        ASTFinding(
            rule_id="py_eval",
            category="A03",
            severity="critical",
            confidence="high",
            title="Dynamic Code Execution via eval",
            explanation="eval() allows arbitrary code execution.",
            remediation="Use safe evaluation.",
            file_path="src/app.py",
            line_start=11,
            line_end=11,
        ),
    ]

    llm_findings = [
        Finding(
            file_path="src/app.py",
            line_start=12,
            line_end=12,
            severity="critical",
            category="A03",
            title="SQL Injection",
            explanation="SQL query formatted directly.",
            remediation="Use parameters.",
            confidence="high",
            source="llm",
            suggested_fix="execute_query(sql, (data,))",
        ),
        # Unmapped finding (file not in diff)
        LLMFindingItem(
            file_path="src/auth.py",
            line_start=5,
            line_end=5,
            severity=Severity.medium,
            category="A07",
            title="Hardcoded Credential",
            explanation="Found test key.",
            remediation="Move to env.",
            confidence=Confidence.medium,
        ),
    ]

    mock_poster = MockGitHubPoster()
    context = RepoContext(
        repository_full_name="acme/web-app",
        pull_request_number=42,
        head_sha="0123456789abcdef0123456789abcdef01234567",
        files_analyzed=2,
        analysis_duration_ms=1250,
    )

    result = aggregate_and_post(
        ast_findings=ast_findings,
        llm_findings=llm_findings,
        diff_text=SAMPLE_DIFF,
        repo_context=context,
        poster=mock_poster,
    )

    assert result.review_id is not None
    assert len(result.posted_findings) == 3
    assert result.summary_stats["inline_comments"] == 2
    assert result.summary_stats["unmapped_comments"] == 1
    assert result.summary_stats["critical_count"] == 2
    assert result.summary_stats["medium_count"] == 1

    # Verify mock poster recorded the review payload with required shape
    assert len(mock_poster.posted_reviews) == 1
    recorded = mock_poster.posted_reviews[0]
    assert recorded["owner"] == "acme"
    assert recorded["repo"] == "web-app"
    assert recorded["pull_number"] == 42

    payload = recorded["payload"]
    assert payload["event"] == "COMMENT"
    assert "acme" in recorded["owner"]
    assert len(payload["comments"]) == 2

    # Check payload comments have all mandatory keys
    for comment in payload["comments"]:
        assert "path" in comment
        assert "line" in comment
        assert "side" in comment
        assert "body" in comment
        assert comment["side"] == "RIGHT"

    # Line 12 comment should include suggestion block
    line_12_comment = next(c for c in payload["comments"] if c["line"] == 12)
    assert "```suggestion" in line_12_comment["body"]
    assert "execute_query(sql, (data,))" in line_12_comment["body"]


def test_all_emitted_severities_accepted_by_db_constraint():
    """Verify that every severity Phase 5 can emit is valid under ck_findings_severity."""
    from codepulse.aggregation.models import SEVERITY_ORDER
    from codepulse.models.tables import Finding as DBFinding

    constraint = next(
        c
        for c in DBFinding.__table__.constraints
        if c.__class__.__name__ == "CheckConstraint" and c.name == "ck_findings_severity"
    )
    sql_text = str(constraint.sqltext)

    # Every severity recognized and emitted by Phase 5 must be in the DB constraint
    for severity in SEVERITY_ORDER.keys():
        assert f"'{severity}'" in sql_text, f"Severity {severity!r} is not allowed by DB constraint!"

