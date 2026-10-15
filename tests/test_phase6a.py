"""Tests for Phase 6a: Diff fetching, preprocessing, and persistence.

Covers:
1. Diff Fetcher: MockDiffFetcher fixtures, create_github_app_jwt RS256 token generation,
   and GitHubDiffFetcher (token exchange, pagination, caching, base64 content).
2. Preprocessor: File filtering (lockfiles, vendored, removed, binary/empty, unsupported,
   oversized, generated code), hunk splitting (<= 4000 tokens), LLM batching (<= 8 chunks,
   <= 32000 tokens), and AnalysisChunk serialization.
3. Category Normalization: Verification that all Python and JS heuristic categories normalize
   to <= 20 chars and match VALID_CATEGORIES (A01-A10, memory_leak), with safe fallback for unknown categories.
4. Cross-Source Deduplication: Merging on (file_path, line_start, category) when titles differ,
   retaining winning confidence, source="merged", and attribution. Non-matching lines/categories do not merge.
5. Engine & Tier 2 Escalation: Inline escalation triggers on critical low/medium findings;
   aggregate_and_post persistence is strictly opt-in (does not write to DB by default).
6. Database Persistence: update_analysis_run_status, record_llm_usage, and idempotent
   persist_analysis_results tested against PostgreSQL (skips cleanly if unreachable, no SQLite).
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from codepulse.aggregation.dedup import deduplicate_and_sort
from codepulse.aggregation.engine import (
    aggregate_and_post,
    check_tier2_escalation,
    normalize_repo_context,
    persist_findings_stub,
    run_tier2_escalation,
)
from codepulse.aggregation.models import (
    Finding,
    RepoContext,
    normalize_category,
)
from codepulse.aggregation.persistence import (
    persist_analysis_results,
    record_llm_usage,
    update_analysis_run_status,
)
from codepulse.analysis.heuristics.base import ASTFinding
from codepulse.analysis.llm_client import MockLLMClient
from codepulse.analysis.llm_schemas import VALID_CATEGORIES, LLMFindingItem, Severity, Confidence
from codepulse.config import Settings, get_settings
from codepulse.ingestion.diff_fetcher import (
    BaseDiffFetcher,
    GitHubDiffFetcher,
    MockDiffFetcher,
    PRFile,
    create_github_app_jwt,
    get_diff_fetcher,
)
from codepulse.ingestion.preprocessor import (
    AnalysisChunk,
    MAX_CHUNK_TOKENS,
    batch_chunks_for_llm,
    estimate_tokens,
    preprocess_pr_files,
    should_filter_file,
    split_patch_into_subpatches,
)
from codepulse.models.tables import AnalysisRun, Finding as DBFinding, LlmUsageLog, Repository


# ── Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def rsa_key_pem() -> bytes:
    """Generate a temporary 2048-bit RSA private key in PEM format."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample Finding for testing."""
    return Finding(
        file_path="src/app.py",
        line_start=10,
        line_end=12,
        severity="high",
        category="A03",
        title="SQL Injection",
        explanation="Untrusted input in query",
        remediation="Use parameterized queries",
        confidence="high",
        source="ast",
        raw_category="A03: Injection",
        suggested_fix="cursor.execute('SELECT * FROM users WHERE id = %s', (val,))",
        diff_line=11,
        diff_start_line=10,
        diff_side="RIGHT",
        is_in_diff=True,
    )


@pytest.fixture
def db_session():
    """Yield a database session connected to PostgreSQL, or skip cleanly if unreachable."""
    settings = get_settings()
    try:
        engine = create_engine(settings.database_url, connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        pytest.skip(f"Docker PostgreSQL unreachable at {settings.database_url}: {exc}")

    session_factory = sessionmaker(bind=engine)
    session: Session = session_factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# ── 1. Diff Fetcher Tests ──────────────────────────────────────────────


class TestDiffFetcher:
    """Tests for MockDiffFetcher, GitHubDiffFetcher, and JWT creation."""

    def test_mock_diff_fetcher_default_files(self) -> None:
        fetcher = MockDiffFetcher()
        files = fetcher.fetch_pr_files("owner", "repo", 42)
        assert len(files) == 5
        filenames = [f.filename for f in files]
        assert "src/app.py" in filenames
        assert "src/index.js" in filenames
        assert "src/clean.py" in filenames
        assert "poetry.lock" in filenames
        assert "node_modules/pkg/index.js" in filenames

        # Verify content retrieval
        app_content = fetcher.fetch_file_content("owner", "repo", "src/app.py", "sha123")
        assert app_content is not None
        assert "eval(" in app_content
        assert fetcher.fetch_file_content("owner", "repo", "nonexistent.py", "sha123") is None

    def test_mock_diff_fetcher_custom_files(self) -> None:
        custom = [PRFile(filename="foo.py", patch="@@ -1 +1 @@\n+print(1)")]
        fetcher = MockDiffFetcher(custom_files=custom)
        files = fetcher.fetch_pr_files("owner", "repo", 1)
        assert len(files) == 1
        assert files[0].filename == "foo.py"

    def test_create_github_app_jwt(self, rsa_key_pem: bytes) -> None:
        token = create_github_app_jwt(123456, rsa_key_pem)
        parts = token.split(".")
        assert len(parts) == 3

        # Decode header
        header_json = base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8")
        header = json.loads(header_json)
        assert header["alg"] == "RS256"
        assert header["typ"] == "JWT"

        # Decode payload
        payload_json = base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8")
        payload = json.loads(payload_json)
        assert payload["iss"] == "123456"
        assert payload["exp"] - payload["iat"] == 600

    def test_create_github_app_jwt_invalid_key(self) -> None:
        with pytest.raises(Exception):
            create_github_app_jwt(123, b"not-a-valid-pem-key")

    def test_github_diff_fetcher_token_cached(self) -> None:
        redis_mock = MagicMock()
        redis_mock.get.return_value = b"cached_token_abc"
        fetcher = GitHubDiffFetcher(
            app_id=1,
            private_key_pem=b"dummy",
            redis_client=redis_mock,
        )
        token = fetcher.get_installation_token(99)
        assert token == "cached_token_abc"
        redis_mock.get.assert_called_once_with("gh_token:99")

    @patch("httpx.Client.post")
    def test_github_diff_fetcher_token_fetch_and_cache(
        self,
        mock_post: MagicMock,
        rsa_key_pem: bytes,
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"token": "fresh_token_xyz"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        redis_mock = MagicMock()
        redis_mock.get.return_value = None

        fetcher = GitHubDiffFetcher(
            app_id=123,
            private_key_pem=rsa_key_pem,
            redis_client=redis_mock,
        )
        token = fetcher.get_installation_token(456)
        assert token == "fresh_token_xyz"
        redis_mock.set.assert_called_once_with("gh_token:456", "fresh_token_xyz", ex=fetcher.token_ttl)

    @patch("httpx.Client.get")
    def test_github_diff_fetcher_paginated_files(self, mock_get: MagicMock) -> None:
        page1 = [{"filename": "f1.py", "patch": "+line1", "status": "added", "additions": 1, "deletions": 0, "changes": 1}]
        resp1 = MagicMock()
        resp1.json.return_value = page1
        resp1.raise_for_status = MagicMock()

        resp2 = MagicMock()
        resp2.json.return_value = []
        resp2.raise_for_status = MagicMock()

        mock_get.side_effect = [resp1, resp2]

        fetcher = GitHubDiffFetcher(token="test_token")
        files = fetcher.fetch_pr_files("org", "repo", 10)
        assert len(files) == 1
        assert files[0].filename == "f1.py"

    @patch("httpx.Client.get")
    def test_github_diff_fetcher_file_content_base64_decode(self, mock_get: MagicMock) -> None:
        encoded = base64.b64encode(b"print('hello world')\n").decode("ascii")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"content": encoded}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        fetcher = GitHubDiffFetcher(token="test_token")
        content = fetcher.fetch_file_content("org", "repo", "main.py", "head_sha")
        assert content == "print('hello world')\n"

    def test_get_diff_fetcher_factory(self) -> None:
        mock_fetcher = get_diff_fetcher(mock_github=True)
        assert isinstance(mock_fetcher, MockDiffFetcher)

        real_fetcher = get_diff_fetcher(mock_github=False)
        assert isinstance(real_fetcher, GitHubDiffFetcher)


# ── 2. Preprocessor Tests ──────────────────────────────────────────────


class TestPreprocessor:
    """Tests for file filtering, hunk splitting, and LLM batching."""

    @pytest.mark.parametrize(
        ("filename", "patch", "status", "changes", "expected_reason"),
        [
            ("poetry.lock", "@@ -1 +1 @@", "modified", 2, "lockfile"),
            ("package-lock.json", "@@ -1 +1 @@", "modified", 2, "lockfile"),
            ("node_modules/express/index.js", "@@ -1 +1 @@", "added", 2, "vendored"),
            ("vendor/bundle/ruby.rb", "@@ -1 +1 @@", "modified", 2, "vendored"),
            ("src/deleted.py", "@@ -1 +0 @@", "removed", 1, "removed"),
            ("assets/logo.png", None, "added", 0, "binary_or_empty_patch"),
            ("README.md", "@@ -1 +1 @@", "modified", 2, "unsupported_language"),
            ("src/huge.py", "@@ -1 +1 @@", "modified", 5001, "oversized"),
        ],
    )
    def test_should_filter_file_reasons(
        self,
        filename: str,
        patch: str | None,
        status: str,
        changes: int,
        expected_reason: str,
    ) -> None:
        pf = PRFile(filename=filename, patch=patch, status=status, changes=changes)
        assert should_filter_file(pf) == expected_reason

    def test_filter_generated_code(self) -> None:
        patch = "@@ -0,0 +1,5 @@\n+// Code generated by protoc-gen-go. DO NOT EDIT.\n+package test\n"
        pf = PRFile(filename="src/test.js", patch=patch)
        assert should_filter_file(pf) == "generated"

    def test_clean_file_passes_filter(self) -> None:
        pf = PRFile(filename="src/main.py", patch="@@ -1 +1 @@\n+print('ok')", status="modified", changes=2)
        assert should_filter_file(pf) is None

    def test_split_patch_single_chunk_under_threshold(self) -> None:
        patch = "@@ -1,3 +1,3 @@\n-old\n+new\n"
        subpatches = split_patch_into_subpatches(patch, max_tokens=1000)
        assert len(subpatches) == 1
        assert subpatches[0][0] == "@@ -1,3 +1,3 @@"

    def test_split_patch_oversized_splits_at_hunks(self) -> None:
        hunk1 = "@@ -1,5 +1,5 @@\n" + "+line\n" * 50
        hunk2 = "@@ -100,5 +100,5 @@\n" + "+another\n" * 50
        combined = f"{hunk1}\n{hunk2}"
        # Force low threshold to cause split
        subpatches = split_patch_into_subpatches(combined, max_tokens=60)
        assert len(subpatches) >= 2
        assert "@@ -1,5 +1,5 @@" in subpatches[0][0]
        assert "@@ -100,5 +100,5 @@" in subpatches[1][0]

    def test_batch_chunks_for_llm(self) -> None:
        chunks = [
            AnalysisChunk(
                file_path=f"file{i}.py",
                language="python",
                source_code="pass",
                diff_text="@@ -1 +1 @@\n+pass",
                hunk_header="@@ -1 +1 @@",
                estimated_tokens=100,
            )
            for i in range(18)
        ]
        batches = batch_chunks_for_llm(chunks, max_chunks=8, max_tokens=32000)
        assert len(batches) == 3
        assert len(batches[0]) == 8
        assert len(batches[1]) == 8
        assert len(batches[2]) == 2

    def test_preprocess_pr_files_integration(self) -> None:
        fetcher = MockDiffFetcher()
        files = fetcher.fetch_pr_files("owner", "repo", 1)
        res = preprocess_pr_files(files, owner="owner", repo="repo", diff_fetcher=fetcher)

        assert res.files_analyzed == 3  # app.py, index.js, clean.py
        assert "poetry.lock" in res.filtered_files
        assert "node_modules/pkg/index.js" in res.filtered_files
        assert len(res.chunks) >= 3
        assert len(res.llm_batches) >= 1

    def test_analysis_chunk_dict_roundtrip(self) -> None:
        chunk = AnalysisChunk(
            file_path="src/app.py",
            language="python",
            source_code="print('hi')",
            diff_text="@@ -1 +1 @@\n+print('hi')",
            hunk_header="@@ -1 +1 @@",
            modified_lines=[1, 2],
            estimated_tokens=25,
        )
        d = chunk.to_dict()
        restored = AnalysisChunk.from_dict(d)
        assert restored.file_path == chunk.file_path
        assert restored.modified_lines == chunk.modified_lines
        assert restored.estimated_tokens == chunk.estimated_tokens

        diff_chunk = chunk.to_diff_chunk()
        assert diff_chunk.file_path == chunk.file_path
        assert diff_chunk.hunk_header == chunk.hunk_header


# ── 3. Category Normalization Tests ────────────────────────────────────


class TestCategoryNormalization:
    """Verifies that all AST heuristic categories normalize correctly and unknown categories fall back safely."""

    def test_all_ast_heuristic_categories_normalize(self) -> None:
        """Scan python and javascript heuristics files for emitted categories."""
        heuristics_dir = Path("src/codepulse/analysis/heuristics")
        emitted_categories: set[str] = set()

        for path in heuristics_dir.glob("*.py"):
            text_content = path.read_text(encoding="utf-8")
            for m in re.finditer(r'category=["\']([^"\']+)["\']', text_content):
                emitted_categories.add(m.group(1))

        assert len(emitted_categories) >= 8, f"Expected at least 8 AST categories, found: {emitted_categories}"

        for raw in emitted_categories:
            normalized = normalize_category(raw)
            assert len(normalized) <= 20, f"Normalized category too long: '{normalized}' from '{raw}'"
            assert normalized in VALID_CATEGORIES, f"Category '{normalized}' not in VALID_CATEGORIES from '{raw}'"

    @pytest.mark.parametrize(
        ("raw_input", "expected"),
        [
            ("A03: Injection", "A03"),
            ("A02: Cryptographic Failures", "A02"),
            ("A05: Security Misconfiguration", "A05"),
            ("A07: Auth Failures", "A07"),
            ("Memory Leak", "memory_leak"),
            ("memory_leak", "memory_leak"),
            ("A01", "A01"),
            ("A10", "A10"),
            ("sql injection", "A03"),
            ("hardcoded secret", "A02"),
            ("unknown random category that is very very long", "A04"),
            ("", "A04"),
        ],
    )
    def test_category_normalization_cases(self, raw_input: str, expected: str) -> None:
        norm = normalize_category(raw_input)
        assert norm == expected
        assert len(norm) <= 20
        assert norm in VALID_CATEGORIES

    def test_finding_from_ast_finding_normalizes_category(self) -> None:
        ast_f = ASTFinding(
            rule_id="PY-SEC-001",
            file_path="src/vuln.py",
            line_start=5,
            line_end=5,
            severity="critical",
            category="A03: Injection",
            title="SQL Injection",
            explanation="Unsanitized query input",
            remediation="Use parameterized queries",
            confidence="high",
        )
        finding = Finding.from_ast_finding(ast_f)
        assert finding.category == "A03"
        assert finding.source == "ast"


# ── 4. Cross-Source Deduplication Tests ────────────────────────────────


class TestCrossSourceDeduplication:
    """Verifies §3.6.4 cross-source merging and DEC-011 behavior."""

    def test_same_line_and_category_different_titles_merges(self) -> None:
        """AST and LLM findings on the same file, line, and category merge even with differing titles."""
        f_ast = Finding(
            file_path="src/app.py",
            line_start=15,
            line_end=15,
            severity="critical",
            category="A03",
            title="SQL Injection via string concatenation",
            explanation="AST detected raw string formatting into SQL cursor.",
            remediation="Use parameterized queries",
            confidence="high",
            source="ast",
        )
        f_llm = Finding(
            file_path="src/app.py",
            line_start=15,
            line_end=15,
            severity="critical",
            category="A03",
            title="Potential SQL injection vulnerability detected",
            explanation="Gemini detected direct variable interpolation in query.",
            remediation="Use parameterized queries",
            confidence="medium",
            source="llm",
        )

        res = deduplicate_and_sort([f_ast, f_llm])
        assert len(res.findings) == 1
        assert res.merged_count == 1

        merged = res.findings[0]
        assert merged.source == "merged"
        assert merged.confidence == "high"  # Higher confidence wins
        assert merged.title == "SQL Injection via string concatenation"
        assert "Also detected by llm" in merged.explanation

    def test_different_line_does_not_merge(self) -> None:
        """Findings on different lines must not merge."""
        f1 = Finding(
            file_path="src/app.py",
            line_start=15,
            line_end=15,
            severity="high",
            category="A03",
            title="SQLi on line 15",
            explanation="Query issue",
            remediation="Fix it",
            confidence="high",
            source="ast",
        )
        f2 = Finding(
            file_path="src/app.py",
            line_start=16,
            line_end=16,
            severity="high",
            category="A03",
            title="SQLi on line 16",
            explanation="Query issue",
            remediation="Fix it",
            confidence="high",
            source="llm",
        )

        res = deduplicate_and_sort([f1, f2])
        assert len(res.findings) == 2
        assert res.merged_count == 0

    def test_different_category_does_not_merge(self) -> None:
        """Findings on the same line with different categories must not merge."""
        f1 = Finding(
            file_path="src/app.py",
            line_start=20,
            line_end=20,
            severity="high",
            category="A03",
            title="SQLi",
            explanation="Query issue",
            remediation="Fix it",
            confidence="high",
            source="ast",
        )
        f2 = Finding(
            file_path="src/app.py",
            line_start=20,
            line_end=20,
            severity="high",
            category="A02",
            title="Hardcoded Secret",
            explanation="Key issue",
            remediation="Fix it",
            confidence="high",
            source="llm",
        )

        res = deduplicate_and_sort([f1, f2])
        assert len(res.findings) == 2
        assert res.merged_count == 0

    def test_llm_winner_over_ast_lower_confidence(self) -> None:
        """When LLM has higher confidence, it wins metadata while noting AST detection."""
        f_ast = Finding(
            file_path="src/app.py",
            line_start=30,
            line_end=30,
            severity="high",
            category="A03",
            title="AST SQLi",
            explanation="AST explanation",
            remediation="AST fix",
            confidence="low",
            source="ast",
        )
        f_llm = Finding(
            file_path="src/app.py",
            line_start=30,
            line_end=30,
            severity="critical",
            category="A03",
            title="LLM SQLi Confirmed",
            explanation="LLM explanation",
            remediation="LLM fix",
            confidence="high",
            source="llm",
        )

        res = deduplicate_and_sort([f_ast, f_llm])
        assert len(res.findings) == 1
        merged = res.findings[0]
        assert merged.confidence == "high"
        assert merged.severity == "critical"
        assert merged.title == "LLM SQLi Confirmed"
        assert merged.source == "merged"
        assert "Also detected by ast" in merged.explanation


# ── 5. Engine Escalation & Persistence Opt-in Tests ────────────────────


class TestEngineEscalationAndPersistenceOptIn:
    """Tests for Tier 2 escalation and opt-in persistence in engine.py."""

    def test_normalize_repo_context_dict_variations(self) -> None:
        d1 = {
            "repository_full_name": "octocat/hello-world",
            "pull_request_number": 42,
            "head_sha": "abc1234",
            "base_sha": "def5678",
            "pr_author": "alice",
        }
        ctx1 = normalize_repo_context(d1)
        assert ctx1.repository_full_name == "octocat/hello-world"
        assert ctx1.pull_request_number == 42

        d2 = {
            "repo_full_name": "octocat/alt",
            "pr_number": 7,
        }
        ctx2 = normalize_repo_context(d2)
        assert ctx2.repository_full_name == "octocat/alt"
        assert ctx2.pull_request_number == 7

        # Passing an existing RepoContext returns it unchanged
        assert normalize_repo_context(ctx1) is ctx1

    def test_check_tier2_escalation_criteria(self) -> None:
        f_crit_med = Finding(
            file_path="a.py", line_start=1, line_end=1, severity="critical", category="A03",
            title="t", explanation="e", remediation="r", confidence="medium", source="ast",
        )
        assert check_tier2_escalation([f_crit_med]) is True

        f_crit_high = Finding(
            file_path="a.py", line_start=1, line_end=1, severity="critical", category="A03",
            title="t", explanation="e", remediation="r", confidence="high", source="ast",
        )
        assert check_tier2_escalation([f_crit_high]) is False

        f_high_med = Finding(
            file_path="a.py", line_start=1, line_end=1, severity="high", category="A03",
            title="t", explanation="e", remediation="r", confidence="medium", source="ast",
        )
        assert check_tier2_escalation([f_high_med]) is False

    def test_run_tier2_escalation_with_mock_client(self) -> None:
        f = Finding(
            file_path="src/app.py",
            line_start=1,
            line_end=1,
            severity="critical",
            category="A03",
            title="SQLi",
            explanation="Unchecked input",
            remediation="Fix it",
            confidence="low",
            source="ast",
        )
        mock_client = MockLLMClient()
        escalated_findings, res = run_tier2_escalation(
            [f],
            diff_text="@@ -1 +1 @@\n+cursor.execute(f'SELECT {user_input}')",
            repo_name="org/repo",
            llm_client=mock_client,
        )
        assert res is not None
        assert len(escalated_findings) == 1
        assert "Verified via Tier 2 escalation" in escalated_findings[0].explanation

    def test_aggregate_and_post_does_not_persist_by_default(self) -> None:
        """aggregate_and_post without db parameter must NOT call persist_analysis_results."""
        with patch("codepulse.aggregation.engine.persist_analysis_results") as mock_persist:
            res = aggregate_and_post(
                ast_findings=[],
                llm_findings=[],
                diff_text="@@ -1,1 +1,1 @@\n+print(1)\n",
                repo_context={"repository_full_name": "org/repo", "pull_request_number": 1},
            )
            assert res is not None
            mock_persist.assert_not_called()

    def test_persist_findings_stub_without_db_returns_zero(self, sample_finding: Finding) -> None:
        ctx = RepoContext(
            repository_full_name="org/repo",
            pull_request_number=1,
            head_sha="sha",
            base_sha="base",
            pr_author="author",
        )
        count = persist_findings_stub([sample_finding], review_id=123, context=ctx, db=None)
        assert count == 0


# ── 6. Database Persistence Integration Tests ──────────────────────────


class TestDatabasePersistence:
    """Integration tests running against Docker PostgreSQL.

    Skips cleanly if PostgreSQL is unreachable.
    """

    def _setup_test_run(self, db: Session) -> tuple[Repository, AnalysisRun]:
        gh_id = int(uuid.uuid4().int % 1_000_000_000)
        repo = Repository(
            github_id=gh_id,
            full_name=f"test-org/repo-{gh_id}",
            installation_id=12345,
            default_branch="main",
            primary_language="Python",
        )
        db.add(repo)
        db.flush()

        run = AnalysisRun(
            id=uuid.uuid4(),
            repository_id=repo.id,
            pull_request_number=1,
            head_sha="a" * 40,
            base_sha="b" * 40,
            pr_author="developer",
            status="pending",
            webhook_received_at=datetime.now(timezone.utc),
        )
        db.add(run)
        db.commit()
        return repo, run

    def test_update_analysis_run_status(self, db_session: Session) -> None:
        _, run = self._setup_test_run(db_session)

        update_analysis_run_status(
            db_session,
            run.id,
            status="running",
            files_analyzed=3,
            chunks_total=5,
            chunks_completed=2,
        )

        db_session.expire_all()
        reloaded = db_session.get(AnalysisRun, run.id)
        assert reloaded is not None
        assert reloaded.status == "running"
        assert reloaded.files_analyzed == 3
        assert reloaded.chunks_total == 5
        assert reloaded.chunks_completed == 2

    def test_record_llm_usage(self, db_session: Session) -> None:
        _, run = self._setup_test_run(db_session)

        record_llm_usage(
            db_session,
            run.id,
            model_version="gemini-3.7-flash",
            input_tokens=150,
            output_tokens=75,
            latency_ms=620,
            cache_hit=False,
        )

        logs = db_session.query(LlmUsageLog).filter(LlmUsageLog.analysis_run_id == run.id).all()
        assert len(logs) == 1
        assert logs[0].model_version == "gemini-3.7-flash"
        assert logs[0].input_tokens == 150
        assert logs[0].output_tokens == 75
        assert logs[0].latency_ms == 620
        assert logs[0].cache_hit is False

    def test_idempotent_persist_analysis_results(
        self,
        db_session: Session,
        sample_finding: Finding,
    ) -> None:
        _, run = self._setup_test_run(db_session)

        f2 = Finding(
            file_path="src/index.js",
            line_start=5,
            line_end=5,
            severity="critical",
            category="A03",
            title="XSS via innerHTML",
            explanation="Unescaped HTML injection",
            remediation="Use textContent",
            confidence="high",
            source="ast",
            diff_line=5,
            is_in_diff=True,
        )

        # 1. First persistence call
        count1 = persist_analysis_results(
            db_session,
            run.id,
            findings=[sample_finding, f2],
            files_analyzed=2,
            chunks_total=2,
            chunks_completed=2,
            analysis_duration_ms=450,
            github_review_id=987654,
            review_posted_at=datetime.now(timezone.utc),
            status="completed",
        )
        assert count1 == 2

        db_findings_1 = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
        assert len(db_findings_1) == 2

        db_session.expire_all()
        reloaded_run = db_session.get(AnalysisRun, run.id)
        assert reloaded_run.total_findings == 2
        assert reloaded_run.critical_count == 1
        assert reloaded_run.high_count == 1
        assert reloaded_run.status == "completed"
        assert reloaded_run.github_review_id == 987654

        # 2. Re-running for same run_id must be idempotent (no duplicate rows)
        # Update findings list with only 1 finding
        count2 = persist_analysis_results(
            db_session,
            run.id,
            findings=[f2],
            files_analyzed=2,
            chunks_total=2,
            chunks_completed=2,
            analysis_duration_ms=460,
            github_review_id=987654,
            review_posted_at=datetime.now(timezone.utc),
            status="completed",
        )
        assert count2 == 1

        db_findings_2 = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
        # Prior findings were deleted, only the 1 finding remains! Zero duplicates.
        assert len(db_findings_2) == 1
        assert db_findings_2[0].title == "XSS via innerHTML"

        db_session.expire_all()
        reloaded_run2 = db_session.get(AnalysisRun, run.id)
        assert reloaded_run2.total_findings == 1
        assert reloaded_run2.critical_count == 1
        assert reloaded_run2.high_count == 0


# ── 7. Finding Serialization Tests ─────────────────────────────────────


class TestFindingSerialization:
    """Verifies Finding.to_dict() and Finding.from_dict() round-trips for task queues."""

    def test_finding_dict_roundtrip(self, sample_finding: Finding) -> None:
        data = sample_finding.to_dict()
        assert isinstance(data, dict)
        assert data["file_path"] == "src/app.py"
        assert data["category"] == "A03"
        assert data["diff_line"] == 11

        restored = Finding.from_dict(data)
        assert restored.file_path == sample_finding.file_path
        assert restored.line_start == sample_finding.line_start
        assert restored.line_end == sample_finding.line_end
        assert restored.severity == sample_finding.severity
        assert restored.category == sample_finding.category
        assert restored.title == sample_finding.title
        assert restored.explanation == sample_finding.explanation
        assert restored.remediation == sample_finding.remediation
        assert restored.confidence == sample_finding.confidence
        assert restored.source == sample_finding.source
        assert restored.diff_line == sample_finding.diff_line
        assert restored.diff_side == sample_finding.diff_side
        assert restored.is_in_diff == sample_finding.is_in_diff
