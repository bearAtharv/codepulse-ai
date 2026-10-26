"""Celery task definitions for PR analysis orchestration (Sections 3.2, 3.5.1, 10.1).

Defines the distributed DAG:
  orchestrate_pr_analysis (chain entry point)
    │
    ├─► fetch_pr_diff
    │     │
    │     ├─► preprocess_and_chunk
    │     │     │
    │     │     ├─► [GROUP: for each chunk]
    │     │     │     ├─► analyze_ast
    │     │     │     └─► analyze_llm
    │     │     │
    │     │     └─► [CHORD callback: aggregate_findings]
    │     │           │
    │     │           └─► post_review_to_github
    │     │                 │
    │     │                 └─► persist_results
"""

from __future__ import annotations

import dataclasses
import logging
import time
from datetime import datetime, timezone
from typing import Any

from celery import chain, chord

from codepulse.aggregation.comments import format_finding_comment
from codepulse.aggregation.dedup import deduplicate_and_sort
from codepulse.aggregation.engine import (
    check_tier2_escalation,
    normalize_repo_context,
    run_tier2_escalation,
)
from codepulse.aggregation.github_poster import get_github_poster
from codepulse.aggregation.line_mapping import map_findings_to_diff_positions
from codepulse.aggregation.models import Finding
from codepulse.aggregation.persistence import (
    persist_analysis_results,
    record_llm_usage,
    update_analysis_run_status,
)
from codepulse.aggregation.summary import compose_review_summary
from codepulse.analysis.ast_engine import analyze_chunk
from codepulse.analysis.llm_engine import analyze_llm
from codepulse.ingestion.diff_fetcher import PRFile, get_diff_fetcher
from codepulse.ingestion.preprocessor import AnalysisChunk, preprocess_pr_files
from codepulse.persistence.database import get_session_factory
from codepulse.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    name="tasks.orchestrate_pr_analysis",
    queue="cp-high",
)
def orchestrate_pr_analysis(
    *,
    installation_id: int,
    repository_full_name: str,
    pull_request_number: int,
    head_sha: str,
    base_sha: str,
    pr_author: str,
    webhook_received_at: str,
    analysis_run_id: str,
) -> dict[str, Any]:
    """Entry point for the PR analysis pipeline (Step 8 of §10.1)."""
    logger.info(
        "orchestrate_pr_analysis started: %s#%d @ %s (run=%s)",
        repository_full_name,
        pull_request_number,
        head_sha[:8],
        analysis_run_id,
    )

    # 1. Update analysis_runs.status = 'running'
    factory = get_session_factory()
    with factory() as db:
        update_analysis_run_status(db, analysis_run_id, status="running")

    payload: dict[str, Any] = {
        "installation_id": installation_id,
        "repository_full_name": repository_full_name,
        "pull_request_number": pull_request_number,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "pr_author": pr_author,
        "webhook_received_at": webhook_received_at,
        "analysis_run_id": analysis_run_id,
    }

    # 2. Dispatch sequential chain: fetch_pr_diff -> preprocess_and_chunk
    workflow = chain(fetch_pr_diff.s(payload), preprocess_and_chunk.s())
    workflow.apply_async()

    return {"status": "running", "analysis_run_id": analysis_run_id}


@celery_app.task(
    name="tasks.fetch_pr_diff",
    queue="cp-high",
)
def fetch_pr_diff(payload: dict[str, Any]) -> dict[str, Any]:
    """Fetch PR files and unified diff patches from GitHub REST API (Step 9 of §10.1)."""
    repo_full_name = payload["repository_full_name"]
    owner, repo = repo_full_name.split("/", 1)
    pr_number = int(payload["pull_request_number"])
    installation_id = int(payload["installation_id"])

    logger.info("fetch_pr_diff: fetching files for %s#%d", repo_full_name, pr_number)
    diff_fetcher = get_diff_fetcher()
    files = diff_fetcher.fetch_pr_files(owner, repo, pr_number, installation_id=installation_id)

    files_data = [dataclasses.asdict(f) for f in files]
    return {
        "files": files_data,
        "context": payload,
    }


@celery_app.task(
    name="tasks.preprocess_and_chunk",
    queue="cp-aggregate",
)
def preprocess_and_chunk(data: dict[str, Any]) -> dict[str, Any]:
    """Filter files, chunk diffs, and dispatch parallel analysis chord (Step 10-11 of §10.1)."""
    context = data["context"]
    repo_full_name = context["repository_full_name"]
    owner, repo = repo_full_name.split("/", 1)
    head_sha = context["head_sha"]
    installation_id = int(context["installation_id"])
    analysis_run_id = context["analysis_run_id"]

    pr_files = [PRFile(**f_dict) for f_dict in data["files"]]
    diff_fetcher = get_diff_fetcher()

    result = preprocess_pr_files(
        pr_files,
        owner=owner,
        repo=repo,
        head_sha=head_sha,
        installation_id=installation_id,
        diff_fetcher=diff_fetcher,
    )

    # If every file is filtered out, set status='skipped' and exit cleanly (§3.2.2)
    if not result.chunks:
        logger.info("All files filtered out for run %s. Marking skipped.", analysis_run_id)
        factory = get_session_factory()
        with factory() as db:
            update_analysis_run_status(
                db,
                analysis_run_id,
                status="skipped",
                files_analyzed=result.files_analyzed,
                chunks_total=0,
                chunks_completed=0,
            )
        return {
            "status": "skipped",
            "analysis_run_id": analysis_run_id,
            "files_analyzed": result.files_analyzed,
        }

    # Build parallel group header for chord
    header = []
    for chunk in result.chunks:
        header.append(analyze_ast_task.s(chunk.to_dict()))

    for batch in result.llm_batches:
        header.append(
            analyze_llm_task.s(
                [c.to_dict() for c in batch],
                repo_full_name,
                batch[0].language,
                analysis_run_id,
            )
        )

    # Body is 3-task chain: aggregate_findings -> post_review_to_github -> persist_results
    body_chain = (
        aggregate_findings.s(
            context=context,
            diff_text=result.unified_diff,
            files_analyzed=result.files_analyzed,
            chunks_total=len(result.chunks),
        )
        | post_review_to_github.s()
        | persist_results.s()
    )

    chord_workflow = chord(header)(body_chain)
    return {
        "status": "dispatched",
        "chunks_total": len(result.chunks),
        "llm_batches": len(result.llm_batches),
    }


@celery_app.task(
    name="tasks.analyze_ast",
    queue="cp-analysis",
)
def analyze_ast_task(chunk_data: dict[str, Any]) -> dict[str, Any]:
    """Execute tree-sitter AST heuristics on a single chunk (Step 12 of §10.1)."""
    chunk = AnalysisChunk.from_dict(chunk_data)
    findings = analyze_chunk(
        chunk.source_code,
        chunk.file_path,
        modified_lines=chunk.modified_lines,
    )
    unified_findings = [Finding.from_ast_finding(f).to_dict() for f in findings]
    return {
        "type": "ast",
        "file_path": chunk.file_path,
        "findings": unified_findings,
    }


@celery_app.task(
    name="tasks.analyze_llm",
    queue="cp-analysis",
)
def analyze_llm_task(
    chunks_data: list[dict[str, Any]],
    repo_name: str,
    language: str,
    analysis_run_id: str,
) -> dict[str, Any]:
    """Execute LLM semantic reasoning on a batch of diff chunks (Step 13 of §10.1)."""
    diff_chunks = [AnalysisChunk.from_dict(d).to_diff_chunk() for d in chunks_data]

    start_time = time.perf_counter()
    llm_result = analyze_llm(diff_chunks, repo_name, language)
    latency_ms = int((time.perf_counter() - start_time) * 1000)

    unified_findings = [Finding.from_llm_finding(f).to_dict() for f in llm_result.findings]
    model_version = getattr(llm_result.metadata, "model_version", None) or "gemini-3.7-flash"
    input_tokens = getattr(llm_result.metadata.token_usage, "input", 0)
    output_tokens = getattr(llm_result.metadata.token_usage, "output", 0)
    usage = {
        "model_version": model_version,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "latency_ms": latency_ms,
        "cache_hit": False,
    }

    return {
        "type": "llm",
        "findings": unified_findings,
        "usage": usage,
    }


@celery_app.task(
    name="tasks.aggregate_findings",
    queue="cp-aggregate",
)
def aggregate_findings(
    results: list[dict[str, Any]],
    context: dict[str, Any],
    diff_text: str,
    files_analyzed: int,
    chunks_total: int,
) -> dict[str, Any]:
    """Chord callback: deduplicate, map lines, format review, and run Tier 2 escalation (Step 14)."""
    logger.info(
        "aggregate_findings: processing %d analysis task results for %s#%s",
        len(results),
        context["repository_full_name"],
        context["pull_request_number"],
    )

    all_findings: list[Finding] = []
    llm_usages: list[dict[str, Any]] = []

    for r in results:
        if r.get("type") == "ast":
            for fd in r.get("findings", []):
                all_findings.append(Finding.from_dict(fd))
        elif r.get("type") == "llm":
            for fd in r.get("findings", []):
                all_findings.append(Finding.from_dict(fd))
            if "usage" in r:
                llm_usages.append(r["usage"])

    # 1. Deduplicate & sort (§3.6.4, DEC-010, DEC-011)
    dedup_result = deduplicate_and_sort(all_findings, max_findings=256)

    # 2. Run Tier 2 escalation inline (§3.4.1)
    if check_tier2_escalation(dedup_result.findings):
        escalated, esc_result = run_tier2_escalation(
            dedup_result.findings,
            diff_text,
            context["repository_full_name"],
        )
        dedup_result.findings = escalated
        if esc_result is not None:
            esc_model = getattr(esc_result.metadata, "model_version", None) or "gemini-2.5-pro"
            esc_in = getattr(esc_result.metadata.token_usage, "input", 0)
            esc_out = getattr(esc_result.metadata.token_usage, "output", 0)
            llm_usages.append({
                "model_version": esc_model,
                "input_tokens": esc_in,
                "output_tokens": esc_out,
                "latency_ms": 0,
                "cache_hit": False,
            })

    # 3. Map findings to diff positions (§3.6.3)
    mapped_findings = map_findings_to_diff_positions(dedup_result.findings, diff_text)
    inline_findings = [f for f in mapped_findings if f.is_in_diff and f.diff_line is not None]
    unmapped_findings = [f for f in mapped_findings if not f.is_in_diff or f.diff_line is None]

    # 4. Compose review summary body
    webhook_received_at = context.get("webhook_received_at")
    if webhook_received_at:
        try:
            start_dt = datetime.fromisoformat(webhook_received_at)
            duration_ms = max(1, int((datetime.now(timezone.utc) - start_dt).total_seconds() * 1000))
        except Exception:
            duration_ms = 0
    else:
        duration_ms = 0

    repo_ctx = normalize_repo_context(context)
    repo_ctx.files_analyzed = files_analyzed
    review_body = compose_review_summary(
        dedup_result=dedup_result,
        files_analyzed=files_analyzed,
        analysis_duration_ms=duration_ms,
        model_version=repo_ctx.model_version,
        unmapped_findings=unmapped_findings,
    )

    # 5. Format inline comment payloads
    comments_payload: list[dict[str, Any]] = []
    for f in inline_findings:
        comment: dict[str, Any] = {
            "path": f.file_path,
            "line": f.diff_line,
            "side": f.diff_side,
            "body": format_finding_comment(f),
        }
        if f.diff_start_line is not None and f.diff_start_line != f.diff_line:
            comment["start_line"] = f.diff_start_line
            comment["start_side"] = f.diff_side
        comments_payload.append(comment)

    review_payload: dict[str, Any] = {
        "event": "COMMENT",
        "body": review_body,
        "comments": comments_payload,
    }
    if context.get("head_sha"):
        review_payload["commit_id"] = context["head_sha"]

    ast_chunks_completed = len([r for r in results if r.get("type") == "ast"])
    completed_chunks = min(ast_chunks_completed, chunks_total) if chunks_total > 0 else len(results)

    return {
        "context": context,
        "findings": [f.to_dict() for f in mapped_findings],
        "review_payload": review_payload,
        "diff_text": diff_text,
        "files_analyzed": files_analyzed,
        "chunks_total": chunks_total,
        "chunks_completed": completed_chunks,
        "analysis_duration_ms": duration_ms,
        "llm_usages": llm_usages,
    }


@celery_app.task(
    name="tasks.post_review_to_github",
    queue="cp-high",
)
def post_review_to_github(data: dict[str, Any]) -> dict[str, Any]:
    """Post inline review comments to GitHub Pull Request Review API (Step 15 of §10.1)."""
    ctx = data["context"]
    repo_full_name = ctx["repository_full_name"]
    owner, repo = repo_full_name.split("/", 1)
    pr_number = int(ctx["pull_request_number"])
    installation_id = int(ctx["installation_id"])

    poster = get_github_poster()
    try:
        response = poster.post_review(
            owner,
            repo,
            pr_number,
            data["review_payload"],
        )
        data["github_review_id"] = response.get("id")
        data["review_posted_at"] = datetime.now(timezone.utc).isoformat()
        logger.info(
            "Successfully posted review %s for %s#%d",
            data["github_review_id"],
            repo_full_name,
            pr_number,
        )
    except Exception as exc:
        # Branch F: Posting failure must never discard findings (§10.2)
        logger.error("Failed to post review for %s#%d: %s", repo_full_name, pr_number, exc)
        data["github_review_id"] = None
        data["review_posted_at"] = None
        data["posting_error"] = str(exc)

    return data


@celery_app.task(
    name="tasks.persist_results",
    queue="cp-aggregate",
)
def persist_results(data: dict[str, Any]) -> dict[str, Any]:
    """Persist findings, LLM telemetry, and final run statistics to PostgreSQL (Step 16)."""
    ctx = data["context"]
    run_id = ctx["analysis_run_id"]
    findings = [Finding.from_dict(fd) for fd in data.get("findings", [])]

    posted_at = (
        datetime.fromisoformat(data["review_posted_at"])
        if data.get("review_posted_at")
        else None
    )

    # Compute total analysis duration from webhook receipt
    duration_ms = data.get("analysis_duration_ms")
    if duration_ms is None or duration_ms == 0:
        webhook_received_at = ctx.get("webhook_received_at")
        if webhook_received_at:
            try:
                start_dt = datetime.fromisoformat(webhook_received_at)
                duration_ms = max(1, int((datetime.now(timezone.utc) - start_dt).total_seconds() * 1000))
            except Exception:
                duration_ms = 0
        else:
            duration_ms = 0

    factory = get_session_factory()
    with factory() as db:
        # 1. Record LLM usage rows
        for u in data.get("llm_usages", []):
            record_llm_usage(
                db=db,
                analysis_run_id=run_id,
                model_version=u["model_version"],
                input_tokens=int(u["input_tokens"]),
                output_tokens=int(u["output_tokens"]),
                latency_ms=int(u.get("latency_ms", 0)),
                cache_hit=False,
            )

        # 2. Persist findings & update analysis_runs (idempotent, single transaction)
        persisted_count = persist_analysis_results(
            db=db,
            analysis_run_id=run_id,
            findings=findings,
            files_analyzed=int(data.get("files_analyzed", 0)),
            chunks_total=int(data.get("chunks_total", 0)),
            chunks_completed=int(data.get("chunks_completed", 0)),
            analysis_duration_ms=duration_ms,
            github_review_id=data.get("github_review_id"),
            review_posted_at=posted_at,
            status="completed",
        )

    logger.info(
        "persist_results completed: %d findings persisted for %s (status=completed, review_id=%s)",
        persisted_count,
        run_id,
        data.get("github_review_id"),
    )

    return {
        "status": "completed",
        "persisted_findings": persisted_count,
        "analysis_run_id": run_id,
        "github_review_id": data.get("github_review_id"),
    }
