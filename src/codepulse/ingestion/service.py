"""Database operations for the webhook ingestion service.

Separated from the HTTP handler so they can be mocked cleanly in tests
without needing a live PostgreSQL instance.
"""

from __future__ import annotations

import logging
import uuid as uuid_mod
from datetime import datetime

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from codepulse.models.tables import AnalysisRun, Repository, WebhookEventLog

logger = logging.getLogger(__name__)


def log_webhook_event(
    session: Session,
    delivery_id: str,
    event_type: str,
    action: str | None = None,
    repository_full_name: str | None = None,
    *,
    processed: bool = False,
    duplicate: bool = False,
) -> None:
    """Insert a row into ``webhook_events_log``.

    Uses ``ON CONFLICT DO NOTHING`` on ``delivery_id`` so that GitHub
    re-deliveries with the same delivery UUID are silently ignored.
    """
    delivery_uuid = uuid_mod.UUID(delivery_id) if delivery_id else uuid_mod.uuid4()
    stmt = (
        pg_insert(WebhookEventLog.__table__)
        .values(
            delivery_id=delivery_uuid,
            event_type=event_type,
            action=action,
            repository_full_name=repository_full_name,
            processed=processed,
            duplicate=duplicate,
        )
        .on_conflict_do_nothing(index_elements=["delivery_id"])
    )
    session.execute(stmt)
    session.commit()


def upsert_repository(
    session: Session,
    repo_data: dict,
    installation_id: int,
) -> int:
    """Insert or update a repository record.  Returns the ``repositories.id``.

    Uses PostgreSQL ``INSERT … ON CONFLICT DO UPDATE`` for atomicity.
    Per Section 10.1, Step 5.
    """
    insert_stmt = pg_insert(Repository.__table__).values(
        github_id=repo_data["id"],
        full_name=repo_data["full_name"],
        installation_id=installation_id,
        default_branch=repo_data.get("default_branch", "main"),
        primary_language=repo_data.get("language"),
    )
    upsert_stmt = (
        insert_stmt.on_conflict_do_update(
            index_elements=["github_id"],
            set_={
                "full_name": insert_stmt.excluded.full_name,
                "installation_id": insert_stmt.excluded.installation_id,
                "default_branch": insert_stmt.excluded.default_branch,
                "primary_language": insert_stmt.excluded.primary_language,
                "updated_at": func.now(),
            },
        )
        .returning(Repository.__table__.c.id)
    )
    result = session.execute(upsert_stmt)
    repo_id: int = result.scalar_one()
    session.commit()
    return repo_id


def create_analysis_run(
    session: Session,
    repo_id: int,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    pr_author: str,
    webhook_received_at: str,
) -> uuid_mod.UUID | None:
    """Create an ``analysis_runs`` row with ``status='pending'``.

    Uses ``ON CONFLICT DO NOTHING`` on the idempotency constraint
    ``(repository_id, pull_request_number, head_sha)`` so that
    DB-level dedup catches anything Redis misses (Section 6.1, Level 2).

    Returns the new run's UUID, or ``None`` if the row already existed.
    """
    received_dt = datetime.fromisoformat(webhook_received_at)
    insert_stmt = (
        pg_insert(AnalysisRun.__table__)
        .values(
            repository_id=repo_id,
            pull_request_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            pr_author=pr_author,
            status="pending",
            webhook_received_at=received_dt,
        )
        .on_conflict_do_nothing(constraint="uq_analysis_runs_repo_pr_sha")
        .returning(AnalysisRun.__table__.c.id)
    )
    result = session.execute(insert_stmt)
    row = result.first()
    session.commit()
    if row is None:
        return None
    return row[0]
