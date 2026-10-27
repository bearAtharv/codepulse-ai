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
import hashlib
import json
import logging
import os
import random
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any

from celery import chain, chord
from celery.exceptions import Ignore, Retry

from codepulse.aggregation.comments import format_finding_comment
from codepulse.aggregation.dedup import (
    deduplicate_and_sort,
    get_vulnerability_family,
    higher_confidence,
    higher_severity,
)
from codepulse.aggregation.engine import (
    check_tier2_escalation,
    normalize_repo_context,
    run_tier2_escalation,
)
from codepulse.aggregation.github_poster import get_github_poster
from codepulse.aggregation.line_mapping import (
    map_findings_to_diff_positions,
    parse_unified_diff,
)
from codepulse.aggregation.models import Finding
from codepulse.aggregation.persistence import (
    persist_analysis_results,
    record_llm_usage,
    update_analysis_run_status,
)
from codepulse.aggregation.summary import compose_review_summary
from codepulse.analysis.ast_engine import analyze_chunk
from codepulse.analysis.circuit_breaker import CircuitBreaker
from codepulse.analysis.llm_engine import DiffChunk, analyze_llm, build_prompt
from codepulse.analysis.llm_schemas import LLMFindingItem
from codepulse.analysis.rate_limiter import TokenBucketRateLimiter
from codepulse.config import get_settings
from codepulse.ingestion.diff_fetcher import PRFile, get_diff_fetcher
from codepulse.ingestion.preprocessor import AnalysisChunk, preprocess_pr_files
from codepulse.metrics import (
    CHUNKS_PER_ANALYSIS,
    RATE_LIMIT_WAIT_SECONDS,
    record_analysis_run,
    record_circuit_breaker,
    record_dead_letter_metric,
    record_finding,
    record_github_api_call,
    record_llm_telemetry,
    record_pipeline_duration,
)
from codepulse.models.tables import AnalysisRun, DeadLetterLog, Finding as DBFinding
from codepulse.persistence.database import (
    get_payload_ref,
    get_redis_client,
    get_session_factory,
    save_payload_ref,
)
from codepulse.worker.celery_app import celery_app

logger = logging.getLogger(__name__)

PROMPT_SCHEMA_VERSION = "v1"


def get_llm_cache_key(prompt_text: str, model_id: str, schema_version: str = PROMPT_SCHEMA_VERSION) -> str:
    """Generate SHA-256 cache key covering prompt content, model id, and schema version (§3.4.5, §3.7.2)."""
    raw = f"{schema_version}:{model_id}:{prompt_text}"
    content_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"llm_cache:{content_hash}"

# §3.5.3 Retry delays (seconds)
FETCH_PR_DIFF_BACKOFF = [5, 15, 45]
ANALYZE_AST_BACKOFF = [2]
ANALYZE_LLM_BACKOFF = [2, 6, 18]
POST_REVIEW_BACKOFF = [3, 9, 27, 81, 243]
PERSIST_RESULTS_BACKOFF = [1, 3, 9]


def is_mock_mode_enabled() -> bool:
    """Return True if mock mode is active for GitHub or LLM."""
    env_github = os.environ.get("MOCK_GITHUB", "").lower()
    env_llm = os.environ.get("MOCK_LLM", "").lower()
    if env_github in ("false", "0", "no") and env_llm in ("false", "0", "no"):
        return False
    if env_github in ("true", "1", "yes") or env_llm in ("true", "1", "yes"):
        return True
    settings = get_settings()
    return bool(settings.mock_github or settings.mock_llm)


def get_retry_delay(backoffs: list[int], retry_count: int) -> int:
    """Return retry delay for the current attempt, with optional test scaling."""
    if is_mock_mode_enabled() and os.environ.get("MOCK_QUICK_RETRIES", "").lower() in ("true", "1", "yes"):
        return 1
    return backoffs[min(retry_count, len(backoffs) - 1)]


def record_dead_letter(
    task_name: str,
    task_id: str | uuid.UUID,
    task_args: dict[str, Any],
    exc: Exception,
    retry_count: int,
) -> None:
    """Durably record a failed task in dead_letter_log (Section 3.5.4)."""
    try:
        if isinstance(task_id, str):
            try:
                task_uuid = uuid.UUID(task_id)
            except Exception:
                task_uuid = uuid.uuid4()
        else:
            task_uuid = task_id

        tb = traceback.format_exc()
        factory = get_session_factory()
        with factory() as db:
            entry = DeadLetterLog(
                task_name=task_name,
                task_id=task_uuid,
                task_args=task_args,
                exception_type=type(exc).__name__,
                exception_message=str(exc),
                traceback=tb if tb and tb != "NoneType: None\n" else str(exc),
                retry_count=retry_count,
                resolved=False,
            )
            db.add(entry)
            db.commit()
    except Exception as db_exc:
        logger.error("Failed to write to dead_letter_log: %s", db_exc)
        try:
            client = get_redis_client()
            client.rpush(
                "dead_letter:fallback",
                json.dumps({
                    "task_name": task_name,
                    "task_id": str(task_id),
                    "task_args": task_args,
                    "exception_type": type(exc).__name__,
                    "exception_message": str(exc),
                    "retry_count": retry_count,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }),
            )
        except Exception:
            pass


def record_terminal_failure(
    analysis_run_id: str,
    error_message: str,
) -> None:
    """Ensure an unrecoverable analysis run transitions to terminal 'failed' status (§10.2)."""
    try:
        factory = get_session_factory()
        with factory() as db:
            update_analysis_run_status(
                db,
                analysis_run_id,
                status="failed",
                error_message=error_message,
            )
    except Exception as exc:
        logger.error("Failed to update terminal status for %s: %s", analysis_run_id, exc)


def normalize_confidence(val: Any) -> str:
    """Normalize confidence to canonical DB values ('high', 'medium', 'low') per §3.7.1."""
    if isinstance(val, (int, float)):
        res = "high" if val >= 0.8 else ("medium" if val >= 0.5 else "low")
        logger.warning("Coerced numeric confidence %s to canonical '%s'", val, res)
        return res
    if isinstance(val, str):
        s = val.strip().lower()
        if s in ("high", "medium", "low"):
            return s
        logger.warning("Coerced unknown string confidence '%s' to 'medium'", val)
        return "medium"
    logger.warning("Coerced unexpected confidence value %r (%s) to 'medium'", val, type(val).__name__)
    return "medium"


def recover_pending_persistence(redis_client: Any, db: Any) -> int:
    """Recover and persist findings saved to Redis when PostgreSQL was unreachable (Branch G)."""
    recovered = 0
    while True:
        raw_run_id = redis_client.lpop("codepulse:pending_persistence")
        if not raw_run_id:
            break
        run_id = raw_run_id if isinstance(raw_run_id, str) else raw_run_id.decode()
        payload = get_payload_ref(f"dead_letter:persist:{run_id}")
        if not payload:
            continue
        findings = [Finding.from_dict(f) for f in payload.get("findings", [])]
        for f in findings:
            f.confidence = normalize_confidence(f.confidence)
        posted_at = (
            datetime.fromisoformat(payload["review_posted_at"])
            if payload.get("review_posted_at")
            else None
        )
        persist_analysis_results(
            db=db,
            analysis_run_id=run_id,
            findings=findings,
            files_analyzed=int(payload.get("files_analyzed", 0)),
            chunks_total=int(payload.get("chunks_total", 0)),
            chunks_completed=int(payload.get("chunks_completed", 0)),
            analysis_duration_ms=int(payload.get("analysis_duration_ms", 0)),
            github_review_id=payload.get("github_review_id"),
            review_posted_at=posted_at,
            status="completed",
        )
        for u in payload.get("llm_usages", []):
            record_llm_usage(
                db=db,
                analysis_run_id=run_id,
                model_version=u["model_version"],
                input_tokens=int(u["input_tokens"]),
                output_tokens=int(u["output_tokens"]),
                latency_ms=int(u.get("latency_ms", 0)),
                cache_hit=False,
            )
        db.commit()
        redis_client.delete(f"dead_letter:persist:{run_id}")
        recovered += 1
    return recovered


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

    try:
        factory = get_session_factory()
        with factory() as db:
            update_analysis_run_status(db, analysis_run_id, status="running")
    except Exception as exc:
        logger.error("Failed to update status to running for %s: %s", analysis_run_id, exc)

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

    try:
        workflow = chain(fetch_pr_diff.s(payload), preprocess_and_chunk.s())
        workflow.apply_async()
    except Exception as exc:
        logger.error("Failed to dispatch workflow chain for %s: %s", analysis_run_id, exc)
        record_terminal_failure(analysis_run_id, error_message=str(exc))
        raise

    return {"status": "running", "analysis_run_id": analysis_run_id}


@celery_app.task(
    bind=True,
    name="tasks.fetch_pr_diff",
    queue="cp-high",
    max_retries=3,
    soft_time_limit=30,
    time_limit=45,
)
def fetch_pr_diff(self: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """Fetch PR files and unified diff patches from GitHub REST API (Step 9 of §10.1)."""
    repo_full_name = payload["repository_full_name"]
    owner, repo = repo_full_name.split("/", 1)
    pr_number = int(payload["pull_request_number"])
    installation_id = int(payload["installation_id"])
    analysis_run_id = payload["analysis_run_id"]

    logger.info(
        "fetch_pr_diff: fetching files for %s#%d (run=%s)",
        repo_full_name,
        pr_number,
        analysis_run_id,
    )

    settings = get_settings()
    is_direct = getattr(self.request, "called_directly", False)
    retries = getattr(self.request, "retries", 0)

    # GitHub Rate Limit Check (§10.2 Branch E)
    if is_mock_mode_enabled() and os.environ.get("MOCK_GITHUB_RATE_LIMIT", "").lower() in ("true", "1", "yes") and retries == 0:
        raw_reset = os.environ.get("MOCK_GITHUB_RESET_TS")
        reset_ts = float(raw_reset) if raw_reset and float(raw_reset) > 0 else (time.time() + 5)
        eta = datetime.fromtimestamp(reset_ts, timezone.utc)
        logger.warning(
            "GitHub rate limit threshold reached (<100 remaining). Rescheduling %s to cp-retry at %s",
            self.name,
            eta.isoformat(),
        )
        raise self.retry(queue="cp-retry", eta=eta)

    # Failure injection (§7.6)
    if settings.mock_github and (
        settings.mock_diff_fetch_failure
        or os.environ.get("MOCK_DIFF_FETCH_FAILURE", "").lower() in ("true", "1", "yes")
    ):
        exc = RuntimeError("Simulated GitHub diff fetch failure (MOCK_DIFF_FETCH_FAILURE)")
        if not is_direct and retries < 3:
            delay = get_retry_delay(FETCH_PR_DIFF_BACKOFF, retries)
            logger.warning(
                "fetch_pr_diff failure injected (attempt %d/3) for %s#%d. Retrying in %ds...",
                retries + 1,
                repo_full_name,
                pr_number,
                delay,
            )
            raise self.retry(exc=exc, countdown=delay)
        else:
            record_terminal_failure(analysis_run_id, error_message="GitHub API unavailable")
            record_dead_letter(
                task_name="tasks.fetch_pr_diff",
                task_id=getattr(self.request, "id", None) or str(uuid.uuid4()),
                task_args=payload,
                exc=exc,
                retry_count=retries,
            )
            raise exc

    try:
        diff_fetcher = get_diff_fetcher()
        files = diff_fetcher.fetch_pr_files(owner, repo, pr_number, installation_id=installation_id)
    except (Retry, Ignore):
        raise
    except Exception as exc:
        if not is_direct and retries < 3:
            delay = get_retry_delay(FETCH_PR_DIFF_BACKOFF, retries)
            logger.warning(
                "fetch_pr_diff failed (attempt %d/3) for %s#%d: %s. Retrying in %ds...",
                retries + 1,
                repo_full_name,
                pr_number,
                exc,
                delay,
            )
            raise self.retry(exc=exc, countdown=delay)
        else:
            logger.error("fetch_pr_diff exhausted all retries for %s#%d: %s", repo_full_name, pr_number, exc)
            record_terminal_failure(analysis_run_id, error_message="GitHub API unavailable")
            record_dead_letter(
                task_name="tasks.fetch_pr_diff",
                task_id=getattr(self.request, "id", None) or str(uuid.uuid4()),
                task_args=payload,
                exc=exc,
                retry_count=retries,
            )
            raise

    files_data = [dataclasses.asdict(f) for f in files]
    logger.info(
        "fetch_pr_diff completed: fetched %d files for %s#%d (run=%s)",
        len(files),
        repo_full_name,
        pr_number,
        analysis_run_id,
    )

    # Pass-by-reference: store files in Redis
    files_ref = f"pr_files:{analysis_run_id}"
    save_payload_ref(files_ref, files_data, ttl=settings.diff_cache_ttl)

    return {
        "files_ref": files_ref,
        "files": files_data,  # fallback for isolated test calls
        "context": payload,
    }


@celery_app.task(
    bind=True,
    name="tasks.preprocess_and_chunk",
    queue="cp-aggregate",
    soft_time_limit=10,
    time_limit=15,
)
def preprocess_and_chunk(self: Any, data: dict[str, Any]) -> dict[str, Any]:
    """Filter files, chunk diffs, and dispatch parallel analysis chord (Step 10-11 of §10.1)."""
    context = data["context"]
    repo_full_name = context["repository_full_name"]
    owner, repo = repo_full_name.split("/", 1)
    head_sha = context["head_sha"]
    installation_id = int(context["installation_id"])
    analysis_run_id = context["analysis_run_id"]

    # Pass-by-reference retrieval
    files_ref = data.get("files_ref")
    files_data = get_payload_ref(files_ref) if files_ref else None
    if files_data is None:
        files_data = data.get("files", [])

    pr_files = [PRFile(**f_dict) for f_dict in files_data]
    diff_fetcher = get_diff_fetcher()

    result = preprocess_pr_files(
        pr_files,
        owner=owner,
        repo=repo,
        head_sha=head_sha,
        installation_id=installation_id,
        diff_fetcher=diff_fetcher,
    )

    logger.info(
        "preprocess_and_chunk: %d files analyzed, %d chunks created for run %s",
        result.files_analyzed,
        len(result.chunks),
        analysis_run_id,
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

    # Pass-by-reference: store unified diff in Redis
    settings = get_settings()
    diff_ref = f"diff:{analysis_run_id}"
    save_payload_ref(diff_ref, result.unified_diff, ttl=settings.diff_cache_ttl)

    # Build parallel group header for chord
    CHUNKS_PER_ANALYSIS.observe(len(result.chunks))
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
            diff_ref=diff_ref,
            files_analyzed=result.files_analyzed,
            chunks_total=len(result.chunks),
        )
        | post_review_to_github.s()
        | persist_results.s()
    )

    chord(header)(body_chain)
    return {
        "status": "dispatched",
        "chunks_total": len(result.chunks),
        "llm_batches": len(result.llm_batches),
    }


@celery_app.task(
    bind=True,
    name="tasks.analyze_ast",
    queue="cp-analysis",
    max_retries=1,
    soft_time_limit=5,
    time_limit=8,
)
def analyze_ast_task(self: Any, chunk_data: dict[str, Any]) -> dict[str, Any]:
    """Execute tree-sitter AST heuristics on a single chunk (Step 12 of §10.1)."""
    chunk = AnalysisChunk.from_dict(chunk_data)
    is_direct = getattr(self.request, "called_directly", False)
    retries = getattr(self.request, "retries", 0)

    try:
        findings = analyze_chunk(
            chunk.source_code,
            chunk.file_path,
            modified_lines=chunk.modified_lines,
        )
    except (Retry, Ignore):
        raise
    except Exception as exc:
        if not is_direct and retries < 1:
            delay = get_retry_delay(ANALYZE_AST_BACKOFF, retries)
            logger.warning(
                "analyze_ast failed for %s. Retrying in %ds...",
                chunk.file_path,
                delay,
            )
            raise self.retry(exc=exc, countdown=delay)
        else:
            record_dead_letter(
                task_name="tasks.analyze_ast",
                task_id=getattr(self.request, "id", None) or str(uuid.uuid4()),
                task_args={"file_path": chunk.file_path},
                exc=exc,
                retry_count=retries,
            )
            raise

    unified_findings = [Finding.from_ast_finding(f).to_dict() for f in findings]
    logger.info(
        "analyze_ast completed: %s (%d findings)",
        chunk.file_path,
        len(unified_findings),
    )
    return {
        "type": "ast",
        "file_path": chunk.file_path,
        "findings": unified_findings,
    }


@celery_app.task(
    bind=True,
    name="tasks.analyze_llm",
    queue="cp-analysis",
    max_retries=3,
    soft_time_limit=15,
    time_limit=20,
)
def analyze_llm_task(
    self: Any,
    chunks_data: list[dict[str, Any]],
    repo_name: str,
    language: str,
    analysis_run_id: str,
    *,
    failure_retries: int = 0,
    rate_limit_deadline: float | None = None,
) -> dict[str, Any]:
    """Execute LLM semantic reasoning on a batch of diff chunks (Step 13 of §10.1)."""
    diff_chunks = [AnalysisChunk.from_dict(d).to_diff_chunk() for d in chunks_data]
    is_direct = getattr(self.request, "called_directly", False)
    settings = get_settings()
    model_id = settings.gemini_model

    # 1. LLM Response Caching (§3.4.5, §3.7.2)
    _, prompt_text = build_prompt(repo_name, language, diff_chunks)
    cache_key = get_llm_cache_key(prompt_text, model_id)
    redis_client = get_redis_client()

    try:
        cached_raw = redis_client.get(cache_key)
        if cached_raw:
            cached_data = json.loads(cached_raw)
            cached_findings = cached_data.get("findings", [])
            cached_model = cached_data.get("model_version", model_id)
            logger.info(
                "analyze_llm cache HIT: run %s (%s, %d chunks, %d findings)",
                analysis_run_id,
                language,
                len(diff_chunks),
                len(cached_findings),
            )
            record_llm_telemetry(cached_model, 0, 0, 0, cache_hit=True)
            return {
                "type": "llm",
                "findings": cached_findings,
                "usage": {
                    "model_version": cached_model,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "latency_ms": 0,
                    "cache_hit": True,
                },
            }
    except Exception as cache_err:
        logger.warning("Error checking LLM cache for %s: %s", cache_key, cache_err)

    # 2. Token-Bucket Rate Limiter (§3.4.6, §11)
    rate_limiter = TokenBucketRateLimiter(redis_client)
    if is_mock_mode_enabled() and os.environ.get("MOCK_RATE_LIMIT", "").lower() in ("true", "1", "yes"):
        allowed, wait_seconds = False, float(os.environ.get("MOCK_RATE_LIMIT_WAIT", "2.0"))
    else:
        allowed, wait_seconds = rate_limiter.acquire(cost=1)

    if not allowed:
        now_ts = time.time()
        timeout_sec = float(os.environ.get("GEMINI_RATE_LIMIT_DEADLINE", "60.0"))
        effective_deadline = (
            rate_limit_deadline if rate_limit_deadline is not None else (now_ts + timeout_sec)
        )

        # Add jitter (§3.4.6, e.g. uniform 0.1 to 1.5 seconds)
        jitter = random.uniform(0.1, 1.5)
        retry_delay = round(max(1.0, wait_seconds + jitter), 2)

        # Overall deadline check or misconfigured RPM <= 0: degrade to AST-only
        if rate_limiter.rpm <= 0 or (now_ts + retry_delay > effective_deadline):
            logger.warning(
                "Gemini rate limit waiting deadline reached (%.1fs) or RPM=%.1f for run %s. Proceeding with AST-only in degraded mode (§3.4.6, §6.4).",
                max(0.0, effective_deadline - now_ts),
                rate_limiter.rpm,
                analysis_run_id,
            )
            return {
                "type": "llm",
                "findings": [],
                "usage": {
                    "model_version": model_id,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "latency_ms": 0,
                    "cache_hit": False,
                },
                "degraded": True,
                "llm_degraded": True,
                "error": "Rate limit wait deadline exceeded",
            }

        logger.warning(
            "Gemini rate limit threshold reached for task %s. Scheduling retry in %.2fs (jitter=%.2fs, deadline in %.1fs, no worker blocking)",
            getattr(self.request, "id", analysis_run_id),
            retry_delay,
            jitter,
            effective_deadline - now_ts,
        )
        RATE_LIMIT_WAIT_SECONDS.labels(api="gemini").inc(retry_delay)
        raise self.retry(
            countdown=retry_delay,
            max_retries=None,
            kwargs={
                "failure_retries": failure_retries,
                "rate_limit_deadline": effective_deadline,
            },
        )

    # 3. Circuit Breaker (§6.3, §10.2 Branch D)
    breaker = CircuitBreaker(redis_client, name="gemini")
    if is_mock_mode_enabled() and os.environ.get("MOCK_LLM_FAILURE", "").lower() in ("true", "1", "yes"):
        breaker.record_failure()
        logger.warning("Simulated LLM failure injected. Breaker state: %s", breaker.get_state())
        allowed_by_breaker = False
    else:
        allowed_by_breaker, breaker_state = breaker.can_execute()

    if not allowed_by_breaker:
        record_circuit_breaker("gemini", 1.0)
        logger.warning(
            "Gemini circuit breaker is OPEN for run %s. Proceeding with AST-only in degraded mode (§6.4).",
            analysis_run_id,
        )
        return {
            "type": "llm",
            "findings": [],
            "usage": {
                "model_version": model_id,
                "input_tokens": 0,
                "output_tokens": 0,
                "latency_ms": 0,
                "cache_hit": False,
            },
            "llm_degraded": True,
            "error": "Circuit breaker OPEN",
        }

    # 4. Invoke LLM Analysis
    start_time = time.perf_counter()
    try:
        llm_result = analyze_llm(diff_chunks, repo_name, language)
        breaker.record_success()
    except (Retry, Ignore):
        raise
    except Exception as exc:
        breaker.record_failure()
        if not is_direct and failure_retries < 3:
            delay = get_retry_delay(ANALYZE_LLM_BACKOFF, failure_retries)
            logger.warning(
                "analyze_llm failed (attempt %d/3) for run %s (%s). Retrying in %ds...",
                failure_retries + 1,
                analysis_run_id,
                language,
                delay,
            )
            raise self.retry(
                exc=exc,
                countdown=delay,
                max_retries=None,
                kwargs={"failure_retries": failure_retries + 1},
            )
        else:
            logger.error(
                "analyze_llm retries exhausted for run %s (%s): %s. Proceeding in degraded mode.",
                analysis_run_id,
                language,
                exc,
            )
            record_dead_letter(
                task_name="tasks.analyze_llm",
                task_id=getattr(self.request, "id", None) or str(uuid.uuid4()),
                task_args={"analysis_run_id": analysis_run_id, "language": language},
                exc=exc,
                retry_count=failure_retries,
            )
            # Catch failure and return degraded result so chord body still runs
            return {
                "type": "llm",
                "findings": [],
                "usage": {
                    "model_version": model_id,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "latency_ms": 0,
                    "cache_hit": False,
                },
                "llm_degraded": True,
                "error": str(exc),
            }

    latency_ms = int((time.perf_counter() - start_time) * 1000)
    unified_findings = [Finding.from_llm_finding(f).to_dict() for f in llm_result.findings]
    model_version = getattr(llm_result.metadata, "model_version", None) or model_id
    input_tokens = getattr(llm_result.metadata.token_usage, "input", 0)
    output_tokens = getattr(llm_result.metadata.token_usage, "output", 0)
    usage = {
        "model_version": model_version,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "latency_ms": latency_ms,
        "cache_hit": False,
    }

    # Cache successful response in Redis (24h TTL per §3.7.2)
    record_llm_telemetry(model_version, input_tokens, output_tokens, latency_ms, cache_hit=False)
    record_circuit_breaker("gemini", 0.0)
    try:
        redis_client.set(
            cache_key,
            json.dumps({"findings": unified_findings, "model_version": model_version}),
            ex=settings.llm_cache_ttl,
        )
    except Exception as cache_err:
        logger.warning("Error caching LLM result for %s: %s", cache_key, cache_err)

    logger.info(
        "analyze_llm completed: run %s (%s, %d chunks, %d findings, %dms, cache_miss)",
        analysis_run_id,
        language,
        len(diff_chunks),
        len(unified_findings),
        latency_ms,
    )

    return {
        "type": "llm",
        "findings": unified_findings,
        "usage": usage,
    }


@celery_app.task(
    bind=True,
    name="tasks.aggregate_findings",
    queue="cp-aggregate",
    soft_time_limit=5,
    time_limit=8,
)
def aggregate_findings(
    self: Any,
    results: list[dict[str, Any]],
    context: dict[str, Any],
    diff_ref: str | None = None,
    diff_text: str | None = None,
    files_analyzed: int = 0,
    chunks_total: int = 0,
) -> dict[str, Any]:
    """Chord callback: deduplicate, map lines, format review, and run Tier 2 escalation (Step 14)."""
    analysis_run_id = context.get("analysis_run_id")
    logger.info(
        "aggregate_findings started: processing %d analysis results for %s#%s (run=%s)",
        len(results),
        context["repository_full_name"],
        context["pull_request_number"],
        analysis_run_id,
    )

    # Retrieve unified diff from Redis if referenced
    if diff_text is None and diff_ref:
        diff_text = get_payload_ref(diff_ref) or ""
    elif diff_text is None:
        diff_text = ""

    all_findings: list[Finding] = []
    llm_usages: list[dict[str, Any]] = []
    llm_degraded = False

    for r in results:
        if r.get("llm_degraded") or r.get("degraded"):
            llm_degraded = True
        if r.get("type") == "ast":
            for fd in r.get("findings", []):
                all_findings.append(Finding.from_dict(fd))
        elif r.get("type") == "llm":
            for fd in r.get("findings", []):
                all_findings.append(Finding.from_dict(fd))
            if "usage" in r:
                llm_usages.append(r["usage"])

    if llm_degraded:
        context["llm_degraded"] = True

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
        degraded_mode=llm_degraded,
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

    # Pass-by-reference: store review payload in Redis
    settings = get_settings()
    review_ref = f"review_payload:{analysis_run_id}"
    save_payload_ref(review_ref, review_payload, ttl=settings.review_payload_cache_ttl)

    crit_count = sum(1 for f in dedup_result.findings if f.severity == "critical")
    high_count = sum(1 for f in dedup_result.findings if f.severity == "high")
    logger.info(
        "aggregate_findings completed: run %s (%d findings, %d critical, %d high)",
        analysis_run_id,
        len(dedup_result.findings),
        crit_count,
        high_count,
    )

    return {
        "context": context,
        "findings": [f.to_dict() for f in mapped_findings],
        "review_ref": review_ref,
        "review_payload": review_payload,  # preserved for fallback / test inspection
        "diff_ref": diff_ref,
        "files_analyzed": files_analyzed,
        "chunks_total": chunks_total,
        "chunks_completed": completed_chunks,
        "analysis_duration_ms": duration_ms,
        "llm_usages": llm_usages,
    }


@celery_app.task(
    bind=True,
    name="tasks.post_review_to_github",
    queue="cp-high",
    max_retries=5,
    soft_time_limit=30,
    time_limit=45,
)
def post_review_to_github(self: Any, data: dict[str, Any]) -> dict[str, Any]:
    """Post inline review comments to GitHub Pull Request Review API (Step 15 of §10.1)."""
    ctx = data["context"]
    repo_full_name = ctx["repository_full_name"]
    owner, repo = repo_full_name.split("/", 1)
    pr_number = int(ctx["pull_request_number"])
    analysis_run_id = ctx.get("analysis_run_id", "")

    # Pass-by-reference retrieval of review payload
    review_ref = data.get("review_ref")
    review_payload = get_payload_ref(review_ref) if review_ref else None
    if review_payload is None:
        review_payload = data.get("review_payload")

    settings = get_settings()
    is_direct = getattr(self.request, "called_directly", False)
    retries = getattr(self.request, "retries", 0)

    # GitHub Rate Limit Check (§10.2 Branch E)
    if is_mock_mode_enabled() and os.environ.get("MOCK_GITHUB_RATE_LIMIT", "").lower() in ("true", "1", "yes") and retries == 0:
        raw_reset = os.environ.get("MOCK_GITHUB_RESET_TS")
        reset_ts = float(raw_reset) if raw_reset and float(raw_reset) > 0 else (time.time() + 5)
        eta = datetime.fromtimestamp(reset_ts, timezone.utc)
        logger.warning(
            "GitHub rate limit threshold reached (<100 remaining). Rescheduling %s to cp-retry at %s",
            self.name,
            eta.isoformat(),
        )
        raise self.retry(queue="cp-retry", eta=eta)

    # Failure injection (§7.6)
    if settings.mock_github and (
        settings.mock_posting_failure
        or os.environ.get("MOCK_POSTING_FAILURE", "").lower() in ("true", "1", "yes")
    ):
        exc = RuntimeError("Simulated GitHub review posting failure (MOCK_POSTING_FAILURE)")
        if not is_direct and retries < 5:
            delay = get_retry_delay(POST_REVIEW_BACKOFF, retries)
            logger.warning(
                "post_review_to_github failure injected (attempt %d/5) for %s#%d. Retrying in %ds...",
                retries + 1,
                repo_full_name,
                pr_number,
                delay,
            )
            raise self.retry(exc=exc, countdown=delay)
        else:
            logger.error(
                "post_review_to_github failure injected exhausted all 5 retries for %s#%d. Storing durable review payload in dead_letter_log.",
                repo_full_name,
                pr_number,
            )
            record_dead_letter(
                task_name="tasks.post_review_to_github",
                task_id=getattr(self.request, "id", None) or str(uuid.uuid4()),
                task_args={
                    "analysis_run_id": analysis_run_id,
                    "review_payload": review_payload,
                    "context": ctx,
                },
                exc=exc,
                retry_count=retries,
            )
            record_dead_letter_metric("tasks.post_review_to_github")
            data["github_review_id"] = None
            data["review_posted_at"] = None
            data["posting_error"] = str(exc)
            return data

    poster = get_github_poster()
    try:
        response = poster.post_review(
            owner,
            repo,
            pr_number,
            review_payload,
        )
        record_github_api_call(f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews", status_code=200)
        data["github_review_id"] = response.get("id")
        data["review_posted_at"] = datetime.now(timezone.utc).isoformat()
        logger.info(
            "post_review_to_github completed: posted review %s for %s#%d (run=%s)",
            data["github_review_id"],
            repo_full_name,
            pr_number,
            analysis_run_id,
        )
    except (Retry, Ignore):
        raise
    except Exception as exc:
        if not is_direct and retries < 5:
            delay = get_retry_delay(POST_REVIEW_BACKOFF, retries)
            logger.warning(
                "post_review_to_github failed (attempt %d/5) for %s#%d: %s. Retrying in %ds...",
                retries + 1,
                repo_full_name,
                pr_number,
                exc,
                delay,
            )
            raise self.retry(exc=exc, countdown=delay)
        else:
            # Branch F: exhausted all retries -> durable dead letter, review_posted_at is NULL, findings preserved
            logger.error(
                "post_review_to_github exhausted all 5 retries for %s#%d: %s. Saving to dead_letter_log.",
                repo_full_name,
                pr_number,
                exc,
            )
            record_dead_letter(
                task_name="tasks.post_review_to_github",
                task_id=getattr(self.request, "id", None) or str(uuid.uuid4()),
                task_args={
                    "analysis_run_id": analysis_run_id,
                    "review_payload": review_payload,
                    "context": ctx,
                },
                exc=exc,
                retry_count=retries,
            )
            record_dead_letter_metric("tasks.post_review_to_github")
            data["github_review_id"] = None
            data["review_posted_at"] = None
            data["posting_error"] = str(exc)

    return data


@celery_app.task(
    bind=True,
    name="tasks.persist_results",
    queue="cp-aggregate",
    max_retries=3,
    soft_time_limit=10,
    time_limit=15,
)
def persist_results(self: Any, data: dict[str, Any]) -> dict[str, Any]:
    """Persist findings, LLM telemetry, and final run statistics to PostgreSQL (Step 16)."""
    ctx = data["context"]
    run_id = ctx["analysis_run_id"]
    findings = [Finding.from_dict(fd) for fd in data.get("findings", [])]

    posted_at = (
        datetime.fromisoformat(data["review_posted_at"])
        if data.get("review_posted_at")
        else None
    )

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

    settings = get_settings()
    is_direct = getattr(self.request, "called_directly", False)
    retries = getattr(self.request, "retries", 0)

    # Failure injection (§7.6)
    if (settings.mock_github or settings.mock_llm) and (
        settings.mock_persist_failure
        or os.environ.get("MOCK_PERSIST_FAILURE", "").lower() in ("true", "1", "yes")
    ):
        exc = RuntimeError("Simulated PostgreSQL connection failure (MOCK_PERSIST_FAILURE)")
        if not is_direct and retries < 3:
            delay = get_retry_delay(PERSIST_RESULTS_BACKOFF, retries)
            logger.warning(
                "persist_results failure injected (attempt %d/3) for run %s. Retrying in %ds...",
                retries + 1,
                run_id,
                delay,
            )
            raise self.retry(exc=exc, countdown=delay)
        else:
            # Branch G: fallback to Redis
            logger.critical("persist_results exhausted all 3 retries for %s. Falling back to Redis.", run_id)
            fallback_data = {
                "analysis_run_id": run_id,
                "findings": [f.to_dict() for f in findings],
                "files_analyzed": int(data.get("files_analyzed", 0)),
                "chunks_total": int(data.get("chunks_total", 0)),
                "chunks_completed": int(data.get("chunks_completed", 0)),
                "analysis_duration_ms": duration_ms,
                "github_review_id": data.get("github_review_id"),
                "review_posted_at": data.get("review_posted_at"),
                "llm_usages": data.get("llm_usages", []),
            }
            save_payload_ref(f"dead_letter:persist:{run_id}", fallback_data, ttl=86400 * 7)
            try:
                client = get_redis_client()
                client.rpush("codepulse:pending_persistence", run_id)
            except Exception:
                pass
            return {
                "status": "fallback_redis",
                "analysis_run_id": run_id,
                "error": str(exc),
            }

    try:
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
                    cache_hit=bool(u.get("cache_hit", False)),
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

            # Record Prometheus metrics (§9.2)
            repo_name = ctx.get("repository_full_name", "")
            record_analysis_run("completed", repo_name)
            if duration_ms:
                record_pipeline_duration(duration_ms / 1000.0, "completed", repo_name)
            for f in findings:
                record_finding(f.severity, f.category, f.source)

            # 3. Graceful degradation flag (§6.4, §10.2 Branch D)
            if data.get("context", {}).get("llm_degraded"):
                run_obj = db.get(AnalysisRun, uuid.UUID(run_id))
                if run_obj:
                    run_obj.reanalysis_needed = True
                    db.commit()
    except (Retry, Ignore):
        raise
    except Exception as exc:
        if not is_direct and retries < 3:
            delay = get_retry_delay(PERSIST_RESULTS_BACKOFF, retries)
            logger.warning(
                "persist_results DB error (attempt %d/3) for run %s: %s. Retrying in %ds...",
                retries + 1,
                run_id,
                exc,
                delay,
            )
            raise self.retry(exc=exc, countdown=delay)
        else:
            # Branch G: Fallback to Redis when Postgres is permanently unreachable
            logger.critical("persist_results exhausted all 3 retries for %s. Falling back to Redis.", run_id)
            fallback_data = {
                "analysis_run_id": run_id,
                "findings": [f.to_dict() for f in findings],
                "files_analyzed": int(data.get("files_analyzed", 0)),
                "chunks_total": int(data.get("chunks_total", 0)),
                "chunks_completed": int(data.get("chunks_completed", 0)),
                "analysis_duration_ms": duration_ms,
                "github_review_id": data.get("github_review_id"),
                "review_posted_at": data.get("review_posted_at"),
                "llm_usages": data.get("llm_usages", []),
            }
            save_payload_ref(f"dead_letter:persist:{run_id}", fallback_data, ttl=86400 * 7)
            try:
                client = get_redis_client()
                client.rpush("codepulse:pending_persistence", run_id)
            except Exception:
                pass
            return {
                "status": "fallback_redis",
                "analysis_run_id": run_id,
                "error": str(exc),
            }

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


# ── Celery Beat Periodic Tasks (§6.4, §10.2 Branch D & G) ─────────────


@celery_app.task(
    name="tasks.drain_pending_persistence_task",
    queue="cp-high",
    soft_time_limit=30,
    time_limit=45,
)
def drain_pending_persistence_task() -> int:
    """Periodic task on Celery Beat (every 60s) to drain Redis pending persistence queue (Branch G)."""
    redis_client = get_redis_client()
    factory = get_session_factory()
    with factory() as db:
        recovered = recover_pending_persistence(redis_client, db)
        if recovered > 0:
            logger.info("drain_pending_persistence_task recovered %d runs from Redis", recovered)
        return recovered


@celery_app.task(
    name="tasks.scan_reanalysis_needed",
    queue="cp-high",
    soft_time_limit=120,
    time_limit=180,
)
def scan_reanalysis_needed() -> int:
    """Periodic task on Celery Beat (every 5 min per §6.4) to re-analyze degraded runs (Option A)."""
    breaker = CircuitBreaker(name="gemini")
    allowed, state = breaker.can_execute()
    if not allowed and state == "OPEN":
        logger.info("Gemini circuit breaker is OPEN. Skipping re-analysis scan (§6.4).")
        return 0

    redis_client = get_redis_client()
    factory = get_session_factory()
    reanalyzed_count = 0

    with factory() as db:
        runs = (
            db.query(AnalysisRun)
            .filter(
                AnalysisRun.reanalysis_needed == True,  # noqa: E712
                AnalysisRun.status == "completed",
            )
            .order_by(AnalysisRun.created_at.asc())
            .limit(10)
            .all()
        )

        for run in runs:
            run_id = str(run.id)
            lock_key = f"lock:reanalyze:{run_id}"
            # Distributed lock: ensure only one worker processes this run
            acquired = redis_client.set(lock_key, "1", nx=True, ex=300)
            if not acquired:
                continue

            try:
                # Cap attempts per run in Redis (cap = 3, judgment call logged in DEC-014)
                attempt_key = f"reanalyze:attempts:{run_id}"
                attempts = redis_client.incr(attempt_key)
                redis_client.expire(attempt_key, 86400)
                if attempts > 3:
                    logger.warning(
                        "Re-analysis attempt cap (3) reached for run %s. Clearing reanalysis_needed flag.",
                        run_id,
                    )
                    run.reanalysis_needed = False
                    run.error_message = "Re-analysis attempts exhausted (cap: 3)"
                    db.commit()
                    continue

                repo = run.repository
                owner, repo_name = repo.full_name.split("/", 1)
                pr_number = run.pull_request_number

                # Check PR head SHA is still the analyzed SHA
                diff_fetcher = get_diff_fetcher()
                try:
                    current_head_sha = diff_fetcher.fetch_pr_head_sha(
                        owner, repo_name, pr_number, installation_id=repo.installation_id
                    ) or run.head_sha
                except Exception:
                    current_head_sha = run.head_sha

                if current_head_sha != run.head_sha:
                    logger.info(
                        "PR %s#%d head SHA moved from %s to %s. Re-analysis superseded.",
                        repo.full_name,
                        pr_number,
                        run.head_sha[:8],
                        current_head_sha[:8],
                    )
                    run.reanalysis_needed = False
                    db.commit()
                    continue

                # Fetch PR files & chunk for LLM analysis
                files = diff_fetcher.fetch_pr_files(owner, repo_name, pr_number, installation_id=repo.installation_id)
                filter_result = preprocess_pr_files(files)
                llm_chunks = filter_result.chunks
                if not llm_chunks:
                    run.reanalysis_needed = False
                    db.commit()
                    continue

                diff_chunks = [c.to_diff_chunk() for c in llm_chunks]
                primary_lang = "python"
                for c in llm_chunks:
                    if c.file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
                        primary_lang = "javascript"
                        break

                # Execute LLM analysis only (not AST again)
                llm_result = analyze_llm(diff_chunks, repo.full_name, primary_lang)
                new_llm_findings = [Finding.from_llm_finding(f) for f in llm_result.findings]

                # Map to diff positions
                diff_text = get_payload_ref(f"diff:{run_id}")
                if not diff_text:
                    patches = [f.patch for f in files if f.patch]
                    diff_text = "\n".join(patches)
                mapped_llm_findings = map_findings_to_diff_positions(new_llm_findings, diff_text)

                # Match against already persisted findings using vulnerability-family merge rule (DEC-011)
                existing_findings = (
                    db.query(DBFinding)
                    .filter(DBFinding.analysis_run_id == run.id)
                    .all()
                )

                # Only match against findings that were actually posted; unposted findings still need posting
                posted_findings = [ef for ef in existing_findings if ef.is_posted]
                unposted_db_findings = [ef for ef in existing_findings if not ef.is_posted]

                matched_count = 0
                unmatched_findings: list[Finding] = []

                for nf in mapped_llm_findings:
                    nf_family = get_vulnerability_family(nf)
                    matched_db_finding: DBFinding | None = None
                    for ef in posted_findings:
                        ef_model = Finding(
                            file_path=ef.file_path,
                            line_start=ef.line_start,
                            line_end=ef.line_end,
                            severity=ef.severity,
                            category=ef.category,
                            title=ef.title,
                            explanation=ef.explanation,
                            remediation=ef.remediation,
                            confidence=ef.confidence,
                            source=ef.source,
                        )
                        if (
                            ef.file_path == nf.file_path
                            and ef.line_start == nf.line_start
                            and ef.category == nf.category
                            and get_vulnerability_family(ef_model) == nf_family
                        ):
                            matched_db_finding = ef
                            break

                    if matched_db_finding is not None:
                        # Matched: update existing finding in place (keep higher severity/confidence)
                        merged_sev = higher_severity(matched_db_finding.severity, nf.severity)
                        merged_conf = higher_confidence(matched_db_finding.confidence, nf.confidence)
                        matched_db_finding.severity = merged_sev.lower()
                        matched_db_finding.confidence = merged_conf.lower()
                        matched_db_finding.source = "merged"
                        if "Also detected by" not in matched_db_finding.explanation and "Also confirmed by" not in matched_db_finding.explanation:
                            matched_db_finding.explanation += " (Also confirmed by LLM analysis)"
                        matched_count += 1
                    else:
                        already_in_unposted = any(
                            (ef.file_path == nf.file_path and ef.line_start == nf.line_start and ef.category == nf.category)
                            for ef in unposted_db_findings
                        )
                        if not already_in_unposted:
                            unmatched_findings.append(nf)

                # Collect all findings that must be posted in follow-up review:
                # previously persisted unposted DB findings + newly detected unmatched findings
                all_unposted_models: list[Finding] = list(unmatched_findings)
                for udb in unposted_db_findings:
                    all_unposted_models.append(
                        Finding(
                            file_path=udb.file_path,
                            line_start=udb.line_start,
                            line_end=udb.line_end,
                            severity=udb.severity,
                            category=udb.category,
                            title=udb.title,
                            explanation=udb.explanation,
                            remediation=udb.remediation,
                            confidence=udb.confidence,
                            source=udb.source,
                            raw_category=udb.raw_llm_category,
                        )
                    )

                mapped_unposted = map_findings_to_diff_positions(all_unposted_models, diff_text) if all_unposted_models else []

                # Post ONE follow-up review if any unposted findings exist
                followup_posted = False
                if mapped_unposted:
                    inline_unposted = [f for f in mapped_unposted if f.is_in_diff and f.diff_line is not None]
                    comments_payload: list[dict[str, Any]] = []
                    for uf in inline_unposted:
                        comment = {
                            "path": uf.file_path,
                            "line": uf.diff_line,
                            "side": uf.diff_side,
                            "body": format_finding_comment(uf),
                        }
                        if uf.diff_start_line is not None and uf.diff_start_line != uf.diff_line:
                            comment["start_line"] = uf.diff_start_line
                            comment["start_side"] = uf.diff_side
                        comments_payload.append(comment)

                    review_body = (
                        f"### 🛡️ CodePulse AI — Follow-up LLM analysis\n\n"
                        f"Follow-up semantic analysis has completed for commit `{run.head_sha[:8]}`.\n\n"
                        f"- **Confirmed existing findings:** {matched_count}\n"
                        f"- **New findings detected:** {len(mapped_unposted)}"
                    )

                    review_payload = {
                        "event": "COMMENT",
                        "body": review_body,
                        "comments": comments_payload,
                        "commit_id": run.head_sha,
                    }

                    poster = get_github_poster()
                    resp_id: int | None = None
                    try:
                        resp = poster.post_review(owner, repo_name, pr_number, review_payload)
                        resp_id = resp.get("id")
                        followup_posted = True
                        logger.info(
                            "Follow-up review posted for %s#%d (review_id=%s)",
                            repo.full_name,
                            pr_number,
                            resp_id,
                        )
                        if resp_id is not None:
                            # Record follow-up review ID in Redis without schema change
                            redis_client.set(f"reanalysis:review_id:{run_id}", str(resp_id), ex=2592000)
                    except Exception as post_err:
                        logger.error(
                            "Failed to post follow-up review for %s#%d: %s. Preserving reanalysis_needed flag and recording dead letter.",
                            repo.full_name,
                            pr_number,
                            post_err,
                        )
                        record_dead_letter(
                            task_name="tasks.post_review_to_github",
                            task_id=str(uuid.uuid4()),
                            task_args={
                                "analysis_run_id": run_id,
                                "review_payload": review_payload,
                                "context": {
                                    "repository_full_name": repo.full_name,
                                    "pull_request_number": pr_number,
                                    "analysis_run_id": run_id,
                                },
                            },
                            exc=post_err,
                            retry_count=attempts,
                        )

                    # Update unposted DB findings to is_posted = True if posting succeeded
                    if followup_posted:
                        for udb in unposted_db_findings:
                            udb.is_posted = True

                    # Insert newly detected unmatched findings into DB (must never be lost)
                    for uf in unmatched_findings:
                        is_posted = bool(followup_posted and uf.is_in_diff and uf.diff_line is not None)
                        db.add(
                            DBFinding(
                                id=uuid.uuid4(),
                                analysis_run_id=run.id,
                                file_path=uf.file_path[:500],
                                line_start=uf.line_start,
                                line_end=uf.line_end,
                                severity=uf.severity.lower(),
                                category=uf.category[:20],
                                title=uf.title[:200],
                                explanation=uf.explanation,
                                remediation=uf.remediation,
                                confidence=uf.confidence.lower(),
                                source="llm",
                                raw_llm_category=uf.raw_category[:50] if uf.raw_category else None,
                                is_posted=is_posted,
                            )
                        )

                # Record LLM usage row in DB
                model_ver = getattr(llm_result.metadata, "model_version", None) or "gemini-3.7-flash"
                in_tok = getattr(llm_result.metadata.token_usage, "input", 0)
                out_tok = getattr(llm_result.metadata.token_usage, "output", 0)
                record_llm_usage(
                    db=db,
                    analysis_run_id=run.id,
                    model_version=model_ver,
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                    latency_ms=0,
                    cache_hit=False,
                )

                # Update AnalysisRun counts & clear flag ONLY IF follow-up review succeeded or no unmatched findings needed posting
                all_db_findings = db.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
                run.total_findings = len(all_db_findings)
                run.critical_count = sum(1 for f in all_db_findings if f.severity.lower() == "critical")
                run.high_count = sum(1 for f in all_db_findings if f.severity.lower() == "high")
                run.medium_count = sum(1 for f in all_db_findings if f.severity.lower() == "medium")
                run.low_count = sum(1 for f in all_db_findings if f.severity.lower() == "low")

                if not mapped_unposted or followup_posted:
                    run.reanalysis_needed = False
                    reanalyzed_count += 1
                    logger.info("Re-analysis completed successfully for run %s", run_id)
                else:
                    logger.warning(
                        "Re-analysis findings recorded but follow-up review posting failed for run %s. Keeping reanalysis_needed=True for retry.",
                        run_id,
                    )

                db.commit()

            finally:
                redis_client.delete(lock_key)

    return reanalyzed_count

