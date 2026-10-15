"""Database persistence for analysis runs, findings, and LLM token usage.

Implements Section 3.7.1 and Step 16 of Section 10.1:
- Idempotently persists deduplicated findings into the 'findings' table
  (deletes prior findings for the same analysis_run_id and re-inserts in one
  transaction so task retries never duplicate rows).
- Updates 'analysis_runs' status, counts, duration, and GitHub review metadata.
- Records token consumption and latency in 'llm_usage_log' (with cache_hit=False).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy.orm import Session

from codepulse.aggregation.models import Finding
from codepulse.models.tables import AnalysisRun, LlmUsageLog
from codepulse.models.tables import Finding as DBFinding

logger = logging.getLogger(__name__)


def _to_uuid(val: str | uuid.UUID) -> uuid.UUID:
    return val if isinstance(val, uuid.UUID) else uuid.UUID(str(val))


def update_analysis_run_status(
    db: Session,
    analysis_run_id: str | uuid.UUID,
    status: str,
    *,
    error_message: str | None = None,
    files_analyzed: int | None = None,
    chunks_total: int | None = None,
    chunks_completed: int | None = None,
) -> None:
    """Update the lifecycle status of an AnalysisRun row."""
    run_uuid = _to_uuid(analysis_run_id)
    run = db.get(AnalysisRun, run_uuid)
    if run is None:
        logger.warning("AnalysisRun %s not found when updating status=%s", run_uuid, status)
        return

    run.status = status
    if error_message is not None:
        run.error_message = error_message
    if files_analyzed is not None:
        run.files_analyzed = files_analyzed
    if chunks_total is not None:
        run.chunks_total = chunks_total
    if chunks_completed is not None:
        run.chunks_completed = chunks_completed

    db.commit()


def record_llm_usage(
    db: Session,
    analysis_run_id: str | uuid.UUID,
    model_version: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
    *,
    cache_hit: bool = False,
) -> None:
    """Insert a telemetry row into llm_usage_log (§3.7.1)."""
    run_uuid = _to_uuid(analysis_run_id)
    log_entry = LlmUsageLog(
        analysis_run_id=run_uuid,
        model_version=model_version[:50],
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=latency_ms,
        cache_hit=cache_hit,
    )
    db.add(log_entry)
    db.commit()


def persist_analysis_results(
    db: Session,
    analysis_run_id: str | uuid.UUID,
    findings: Sequence[Finding],
    *,
    files_analyzed: int = 0,
    chunks_total: int = 0,
    chunks_completed: int = 0,
    analysis_duration_ms: int = 0,
    github_review_id: int | str | None = None,
    review_posted_at: datetime | None = None,
    status: str = "completed",
) -> int:
    """Idempotently persist findings and finalize the AnalysisRun record.

    Deletes any existing findings for ``analysis_run_id`` and inserts the current
    batch within a single transaction so re-executing ``persist_results`` never
    creates duplicate rows.

    Returns:
        Count of persisted findings.
    """
    run_uuid = _to_uuid(analysis_run_id)

    # 1. Delete existing findings for this run (idempotency guarantee)
    db.query(DBFinding).filter(DBFinding.analysis_run_id == run_uuid).delete(
        synchronize_session=False
    )

    # 2. Insert findings
    review_was_posted = review_posted_at is not None
    db_findings: list[DBFinding] = []
    for f in findings:
        is_posted = bool(review_was_posted and f.is_in_diff and f.diff_line is not None)
        db_findings.append(
            DBFinding(
                id=uuid.uuid4(),
                analysis_run_id=run_uuid,
                file_path=f.file_path[:500],
                line_start=f.line_start,
                line_end=f.line_end,
                severity=f.severity.lower(),
                category=f.category[:20],
                title=f.title[:200],
                explanation=f.explanation,
                remediation=f.remediation,
                confidence=f.confidence.lower(),
                source=f.source.lower(),
                raw_llm_category=f.raw_category[:50] if f.raw_category else None,
                is_posted=is_posted,
            )
        )
    if db_findings:
        db.add_all(db_findings)

    # 3. Update AnalysisRun summary statistics
    run = db.get(AnalysisRun, run_uuid)
    if run is not None:
        run.status = status
        run.files_analyzed = files_analyzed
        run.chunks_total = chunks_total
        run.chunks_completed = chunks_completed
        run.total_findings = len(findings)
        run.critical_count = sum(1 for f in findings if f.severity.lower() == "critical")
        run.high_count = sum(1 for f in findings if f.severity.lower() == "high")
        run.medium_count = sum(1 for f in findings if f.severity.lower() == "medium")
        run.low_count = sum(1 for f in findings if f.severity.lower() == "low")
        run.analysis_duration_ms = analysis_duration_ms
        run.github_review_id = (
            int(github_review_id) if isinstance(github_review_id, (int, str)) and str(github_review_id).isdigit() else None
        )
        run.review_posted_at = review_posted_at

    db.commit()
    logger.info(
        "Persisted %d findings for analysis_run=%s (status=%s, review_id=%s)",
        len(db_findings),
        run_uuid,
        status,
        github_review_id,
    )
    return len(db_findings)
