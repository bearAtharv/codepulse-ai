"""Aggregation and Review Posting Pipeline Engine.

Coordinates the end-to-end post-analysis workflow (Sections 3.5 & 3.6):
1. Normalizes findings from AST and LLM engines into unified Finding models.
2. Deduplicates colliding findings on (file, line, category, title) with confidence merge.
3. Sorts findings by severity (critical first) and truncates at GitHub's 256-comment limit.
4. Runs inline Tier 2 escalation via gemini-2.5-pro for critical low/medium-confidence findings (§3.4.1).
5. Maps findings to diff hunk lines (line, start_line, side).
6. Composes a markdown summary and formats inline comment suggestions.
7. Posts atomic review to GitHub PR Review API (or records in MockGitHubPoster).
8. Persists deduplicated findings and run statistics to PostgreSQL (§3.7.1).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Sequence

from codepulse.aggregation.comments import format_finding_comment
from codepulse.aggregation.dedup import MAX_REVIEW_COMMENTS, deduplicate_and_sort
from codepulse.aggregation.github_poster import BaseGitHubPoster, get_github_poster
from codepulse.aggregation.line_mapping import map_findings_to_diff_positions
from codepulse.aggregation.models import (
    CONFIDENCE_ORDER,
    AggregationResult,
    Finding,
    RepoContext,
)
from codepulse.aggregation.persistence import persist_analysis_results
from codepulse.aggregation.summary import compose_review_summary
from codepulse.analysis.heuristics.base import ASTFinding
from codepulse.analysis.llm_client import BaseLLMClient
from codepulse.analysis.llm_engine import DiffChunk, LLMAnalysisResult, analyze_llm
from codepulse.analysis.llm_schemas import LLMFindingItem
from codepulse.config import Settings, get_settings

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ── Tier 2 Escalation & Persistence Wiring (Phase 6) ───────────────────


def check_tier2_escalation(findings: Sequence[Finding]) -> bool:
    """Check if any finding warrants escalation to Tier 2 (Gemini 2.5 Pro).

    Per §3.4.1 and DEC-010:
    Critical severity findings with low or medium confidence trigger
    re-analysis by the larger escalation model.
    """
    for f in findings:
        if f.severity.lower() == "critical" and f.confidence.lower() in ("low", "medium"):
            logger.info(
                "Tier 2 escalation warranted for finding %s:%d (%s, conf=%s)",
                f.file_path,
                f.line_start,
                f.title,
                f.confidence,
            )
            return True
    return False


def run_tier2_escalation(
    findings: Sequence[Finding],
    diff_text: str,
    repo_name: str,
    *,
    chunks: Sequence[DiffChunk] | None = None,
    llm_client: BaseLLMClient | None = None,
    settings: Settings | None = None,
) -> tuple[list[Finding], LLMAnalysisResult | None]:
    """Run inline Tier 2 escalation with gemini-2.5-pro for critical low/medium findings."""
    if not check_tier2_escalation(findings):
        return list(findings), None

    if settings is None:
        settings = get_settings()

    escalation_model = settings.gemini_escalation_model
    affected_files = {
        f.file_path
        for f in findings
        if f.severity.lower() == "critical" and f.confidence.lower() in ("low", "medium")
    }

    if chunks:
        escalation_chunks = [c for c in chunks if c.file_path in affected_files]
    else:
        escalation_chunks = [
            DiffChunk(
                file_path=fp,
                hunk_header="@@ -1,1 +1,1 @@",
                content=diff_text or f"# Escalation context for {fp}",
            )
            for fp in sorted(affected_files)
        ]

    if not escalation_chunks:
        return list(findings), None

    logger.info(
        "Running inline Tier 2 escalation with model=%s on %d chunk(s)",
        escalation_model,
        len(escalation_chunks),
    )
    escalation_result = analyze_llm(
        chunks=escalation_chunks,
        repo_name=repo_name,
        language="python",
        client=llm_client,
        model=escalation_model,
        mock_llm=settings.mock_llm,
        api_key=settings.gemini_api_key,
    )

    escalated_by_file_cat: dict[tuple[str, str], LLMFindingItem] = {}
    for ef in escalation_result.findings:
        escalated_by_file_cat[(ef.file_path, ef.category)] = ef

    updated: list[Finding] = []
    for f in findings:
        if f.severity.lower() == "critical" and f.confidence.lower() in ("low", "medium"):
            match = escalated_by_file_cat.get((f.file_path, f.category))
            if match is not None:
                new_conf = (
                    match.confidence.value.lower()
                    if hasattr(match.confidence, "value")
                    else str(match.confidence).lower()
                )
                if CONFIDENCE_ORDER.get(new_conf, 0) >= CONFIDENCE_ORDER.get(f.confidence.lower(), 0):
                    f.confidence = new_conf
                tag = f"*(Verified via Tier 2 escalation: `{escalation_model}`)*"
                if tag not in f.explanation:
                    f.explanation = f"{f.explanation}\n\n{tag}"
        updated.append(f)

    return updated, escalation_result


def persist_findings_stub(
    findings: Sequence[Finding],
    review_id: int | str | None,
    context: RepoContext,
    *,
    db: Session | None = None,
    analysis_run_id: str | None = None,
    chunks_total: int = 0,
    chunks_completed: int = 0,
    review_posted_at: datetime | None = None,
) -> int:
    """Persist findings to PostgreSQL when db session and analysis_run_id are supplied."""
    if db is not None and analysis_run_id is not None:
        posted_ts = review_posted_at or (
            datetime.now(timezone.utc) if review_id is not None else None
        )
        return persist_analysis_results(
            db=db,
            analysis_run_id=analysis_run_id,
            findings=findings,
            files_analyzed=context.files_analyzed,
            chunks_total=chunks_total,
            chunks_completed=chunks_completed,
            analysis_duration_ms=context.analysis_duration_ms,
            github_review_id=review_id,
            review_posted_at=posted_ts,
        )

    logger.debug(
        "persist_findings_stub (no DB session): %d findings for %s#%d (review_id=%s)",
        len(findings),
        context.repository_full_name,
        context.pull_request_number,
        review_id,
    )
    return 0


# ── Pipeline Orchestrator ──────────────────────────────────────────────


def normalize_repo_context(
    repo_context: RepoContext | dict[str, Any],
    settings: Settings | None = None,
) -> RepoContext:
    """Convert a dictionary or RepoContext into a canonical RepoContext."""
    if isinstance(repo_context, RepoContext):
        return repo_context

    if settings is None:
        settings = get_settings()

    repo_full_name = repo_context.get(
        "repository_full_name",
        repo_context.get("repo_full_name", "unknown/unknown"),
    )
    pr_number = repo_context.get(
        "pull_request_number",
        repo_context.get("pr_number", 0),
    )
    return RepoContext(
        repository_full_name=repo_full_name,
        pull_request_number=int(pr_number),
        head_sha=str(repo_context.get("head_sha", "")),
        base_sha=str(repo_context.get("base_sha", "")),
        pr_author=str(repo_context.get("pr_author", "")),
        files_analyzed=int(repo_context.get("files_analyzed", 1)),
        analysis_duration_ms=int(repo_context.get("analysis_duration_ms", 0)),
        model_version=str(repo_context.get("model_version", settings.gemini_model)),
    )


def aggregate_and_post(
    ast_findings: Sequence[ASTFinding | Finding],
    llm_findings: Sequence[LLMFindingItem | Finding],
    diff_text: str,
    repo_context: RepoContext | dict[str, Any],
    *,
    poster: BaseGitHubPoster | None = None,
    llm_client: BaseLLMClient | None = None,
    db: Session | None = None,
    analysis_run_id: str | None = None,
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
        llm_client: Optional explicit LLM client for Tier 2 escalation.
        db: Optional SQLAlchemy Session for persisting results.
        analysis_run_id: Optional UUID string of the AnalysisRun record.
        settings: Optional app settings override.
        max_findings: Cap on inline comments (defaults to 256).

    Returns:
        AggregationResult containing the review ID, posted payload, and summary stats.
    """
    if settings is None:
        settings = get_settings()

    context = normalize_repo_context(repo_context, settings)

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

    # 3. Tier 2 escalation (inline with gemini-2.5-pro if critical + low/medium confidence)
    escalation_needed = check_tier2_escalation(dedup_result.findings)
    if escalation_needed:
        escalated_findings, _ = run_tier2_escalation(
            dedup_result.findings,
            diff_text,
            context.repository_full_name,
            llm_client=llm_client,
            settings=settings,
        )
        dedup_result.findings = escalated_findings

    # 4. Map findings to diff positions
    mapped_findings = map_findings_to_diff_positions(dedup_result.findings, diff_text)

    # 5. Partition inline comments vs unmapped findings
    inline_findings = [f for f in mapped_findings if f.is_in_diff and f.diff_line is not None]
    unmapped_findings = [f for f in mapped_findings if not f.is_in_diff or f.diff_line is None]

    # 6. Format inline comment payloads
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

    # 7. Compose review body summary
    review_body = compose_review_summary(
        dedup_result=dedup_result,
        files_analyzed=context.files_analyzed,
        analysis_duration_ms=context.analysis_duration_ms,
        model_version=context.model_version,
        unmapped_findings=unmapped_findings,
    )

    # 8. Construct final GitHub Review API payload
    review_payload: dict[str, Any] = {
        "event": "COMMENT",
        "body": review_body,
        "comments": comments_payload,
    }
    if context.head_sha:
        review_payload["commit_id"] = context.head_sha

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

    # 10. Persist findings if DB session provided
    persist_findings_stub(
        mapped_findings,
        review_id,
        context,
        db=db,
        analysis_run_id=analysis_run_id,
    )

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
