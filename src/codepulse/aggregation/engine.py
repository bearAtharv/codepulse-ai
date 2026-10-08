"""Aggregation and Review Posting Pipeline Engine.

Coordinates the end-to-end post-analysis workflow (Sections 3.5 & 3.6):
1. Normalizes findings from AST and LLM engines into unified Finding models.
2. Deduplicates colliding findings on (file, line, category, title) with confidence merge.
3. Sorts findings by severity (critical first) and truncates at GitHub's 256-comment limit.
4. Maps findings to diff hunk lines (line, start_line, side).
5. Composes a markdown summary and formats inline comment suggestions.
6. Stubs for Tier 2 escalation (§3.4.1) and PostgreSQL persistence (§3.7.1).
7. Posts atomic review to GitHub PR Review API (or records in MockGitHubPoster).
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from codepulse.aggregation.comments import format_finding_comment
from codepulse.aggregation.dedup import MAX_REVIEW_COMMENTS, deduplicate_and_sort
from codepulse.aggregation.github_poster import BaseGitHubPoster, get_github_poster
from codepulse.aggregation.line_mapping import map_findings_to_diff_positions
from codepulse.aggregation.models import (
    AggregationResult,
    Finding,
    RepoContext,
)
from codepulse.aggregation.summary import compose_review_summary
from codepulse.analysis.heuristics.base import ASTFinding
from codepulse.analysis.llm_schemas import LLMFindingItem
from codepulse.config import Settings, get_settings

logger = logging.getLogger(__name__)


# ── Stubs for Phase 6 (Celery & Persistence Integration) ───────────────


def check_tier2_escalation(findings: Sequence[Finding]) -> bool:
    """Check if any finding warrants escalation to Tier 2 (Gemini 2.5 Pro).

    Per §3.4.1 and DEC-010:
    Critical severity findings with low or medium confidence trigger
    re-analysis by the larger escalation model.

    TODO (Phase 6): Spawn Celery subtask on 'cp-analysis' queue running
    escalation prompt with gemini-2.5-pro before final review posting.
    """
    for f in findings:
        if f.severity.lower() == "critical" and f.confidence.lower() in ("low", "medium"):
            logger.info(
                "[STUB] Tier 2 escalation warranted for finding %s:%d (%s, conf=%s)",
                f.file_path,
                f.line_start,
                f.title,
                f.confidence,
            )
            return True
    return False


def persist_findings_stub(
    findings: Sequence[Finding],
    review_id: int | str | None,
    context: RepoContext,
) -> None:
    """Stub for persisting analysis findings to PostgreSQL (§3.7.1).

    TODO (Phase 6): Save findings to 'findings' table and update 'analysis_runs'
    record with total_findings, severity counts, and review_posted_at within the
    Celery task DB session lifecycle.
    """
    logger.debug(
        "[STUB] persist_findings_stub: %d findings for %s#%d (review_id=%s)",
        len(findings),
        context.repository_full_name,
        context.pull_request_number,
        review_id,
    )


# ── Pipeline Orchestrator ──────────────────────────────────────────────


def aggregate_and_post(
    ast_findings: Sequence[ASTFinding | Finding],
    llm_findings: Sequence[LLMFindingItem | Finding],
    diff_text: str,
    repo_context: RepoContext | dict[str, Any],
    *,
    poster: BaseGitHubPoster | None = None,
    settings: Settings | None = None,
    max_findings: int = MAX_REVIEW_COMMENTS,
) -> AggregationResult:
    """Execute finding aggregation, line mapping, formatting, and review posting.

    Args:
        ast_findings: Findings produced by Phase 3 AST heuristics.
        llm_findings: Findings produced by Phase 4 LLM analysis.
        diff_text: Unified diff string for the pull request.
        repo_context: Context metadata (repository name, PR number, etc.).
        poster: Optional explicit GitHub review poster (defaults to configured poster).
        settings: Optional app settings override.
        max_findings: Cap on inline comments (defaults to 256).

    Returns:
        AggregationResult containing the review ID, posted payload, and summary stats.
    """
    if settings is None:
        settings = get_settings()

    # Normalize repo_context
    if isinstance(repo_context, dict):
        repo_full_name = repo_context.get(
            "repository_full_name",
            repo_context.get("repo_full_name", "unknown/unknown"),
        )
        pr_number = repo_context.get(
            "pull_request_number",
            repo_context.get("pr_number", 0),
        )
        context = RepoContext(
            repository_full_name=repo_full_name,
            pull_request_number=int(pr_number),
            head_sha=str(repo_context.get("head_sha", "")),
            base_sha=str(repo_context.get("base_sha", "")),
            pr_author=str(repo_context.get("pr_author", "")),
            files_analyzed=int(repo_context.get("files_analyzed", 1)),
            analysis_duration_ms=int(repo_context.get("analysis_duration_ms", 0)),
            model_version=str(repo_context.get("model_version", settings.gemini_model)),
        )
    else:
        context = repo_context

    # 1. Adapt findings into unified Finding objects
    unified_findings: list[Finding] = []
    for f in ast_findings:
        if isinstance(f, Finding):
            unified_findings.append(f)
        elif isinstance(f, ASTFinding):
            unified_findings.append(Finding.from_ast_finding(f))
        else:
            logger.warning("Unrecognized AST finding type: %s", type(f))

    for f in llm_findings:
        if isinstance(f, Finding):
            unified_findings.append(f)
        elif isinstance(f, LLMFindingItem):
            unified_findings.append(Finding.from_llm_finding(f))
        else:
            logger.warning("Unrecognized LLM finding type: %s", type(f))

    # 2. Deduplicate, merge collisions, sort by severity, truncate to max_findings
    dedup_result = deduplicate_and_sort(unified_findings, max_findings=max_findings)

    # 3. Map findings to diff positions
    mapped_findings = map_findings_to_diff_positions(dedup_result.findings, diff_text)

    # 4. Partition inline comments vs unmapped findings
    inline_findings = [f for f in mapped_findings if f.is_in_diff and f.diff_line is not None]
    unmapped_findings = [f for f in mapped_findings if not f.is_in_diff or f.diff_line is None]

    # 5. Format inline comment payloads
    comments_payload: list[dict[str, Any]] = []
    for f in inline_findings:
        comment: dict[str, Any] = {
            "path": f.file_path,
            "line": f.diff_line,
            "side": f.diff_side,
            "body": format_finding_comment(f),
        }
        if f.diff_start_line is not None and f.diff_start_line < f.diff_line:
            comment["start_line"] = f.diff_start_line
            comment["start_side"] = f.diff_side
        comments_payload.append(comment)

    # 6. Compose review body summary
    review_body = compose_review_summary(
        dedup_result=dedup_result,
        files_analyzed=context.files_analyzed,
        analysis_duration_ms=context.analysis_duration_ms,
        model_version=context.model_version,
        unmapped_findings=unmapped_findings,
    )

    # 7. Construct final GitHub Review API payload
    review_payload: dict[str, Any] = {
        "event": "COMMENT",
        "body": review_body,
        "comments": comments_payload,
    }
    if context.head_sha:
        review_payload["commit_id"] = context.head_sha

    # 8. Check Tier 2 escalation (stub)
    escalation_needed = check_tier2_escalation(mapped_findings)

    # 9. Post review via GitHub poster
    if poster is None:
        poster = get_github_poster(settings=settings)

    review_response = poster.post_review(
        owner=context.owner,
        repo=context.repo,
        pull_number=context.pull_request_number,
        payload=review_payload,
    )
    review_id = review_response.get("id")

    # 10. Persistence stub
    persist_findings_stub(mapped_findings, review_id, context)

    # 11. Compile summary statistics
    summary_stats = {
        "total_raw": dedup_result.total_raw,
        "deduplicated": len(dedup_result.findings),
        "merged": dedup_result.merged_count,
        "truncated": dedup_result.truncated_count,
        "inline_comments": len(comments_payload),
        "unmapped_comments": len(unmapped_findings),
        "critical_count": sum(1 for f in dedup_result.findings if f.severity.lower() == "critical"),
        "high_count": sum(1 for f in dedup_result.findings if f.severity.lower() == "high"),
        "medium_count": sum(1 for f in dedup_result.findings if f.severity.lower() == "medium"),
        "low_count": sum(1 for f in dedup_result.findings if f.severity.lower() == "low"),
    }

    return AggregationResult(
        review_id=review_id,
        review_body=review_body,
        comments_payload=comments_payload,
        posted_findings=mapped_findings,
        summary_stats=summary_stats,
        escalation_needed=escalation_needed,
        raw_response=review_response,
    )
