"""Admin endpoints for operational management (Section 3.5.4, 6.5)."""

from __future__ import annotations

import hmac
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from codepulse.aggregation.github_poster import get_github_poster
from codepulse.config import get_settings
from codepulse.models.tables import AnalysisRun, DeadLetterLog, Finding as DBFinding
from codepulse.persistence.database import get_db_session, get_payload_ref

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

KNOWN_DEV_KEYS = {
    "dev_admin_key_not_for_production",
    "dev_admin_key",
    "secret",
    "admin",
    "password",
    "test",
}


def verify_admin_auth(
    authorization: str | None = Header(default=None),
) -> None:
    """Verify admin bearer token using constant-time comparison."""
    settings = get_settings()

    # 1. If ADMIN_API_KEY is not set, endpoint is disabled (503)
    if not settings.admin_api_key or not settings.admin_api_key.strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API is disabled: ADMIN_API_KEY is not configured",
        )

    # 2. Refuse dev keys in production
    env = (settings.environment or "development").lower()
    if env in ("production", "prod"):
        if settings.admin_api_key in KNOWN_DEV_KEYS or len(settings.admin_api_key) < 16:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Insecure ADMIN_API_KEY rejected in production environment",
            )

    # 3. Authenticate with bearer token
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header (Bearer token required)",
        )

    token = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(token, settings.admin_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin API key",
        )


@router.post("/retry-posting/{analysis_run_id}")
def retry_posting(
    analysis_run_id: str,
    db: Session = Depends(get_db_session),
    _: None = Depends(verify_admin_auth),
) -> JSONResponse:
    """Retry posting an unposted review to GitHub using durably stored review payload."""
    try:
        run_uuid = uuid.UUID(analysis_run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid analysis_run_id format (UUID required)")

    # 1. Lookup AnalysisRun
    run = db.get(AnalysisRun, run_uuid)
    if not run:
        raise HTTPException(status_code=404, detail=f"Analysis run {analysis_run_id} not found")

    # 2. Find durable review payload in dead_letter_log
    stmt = (
        select(DeadLetterLog)
        .where(
            DeadLetterLog.task_name.in_(["tasks.post_review_to_github", "post_review_to_github"]),
            DeadLetterLog.resolved == False,  # noqa: E712
        )
        .order_by(DeadLetterLog.id.desc())
    )
    dead_letters = db.execute(stmt).scalars().all()
    target_dl: DeadLetterLog | None = None
    review_payload: dict[str, Any] | None = None

    for dl in dead_letters:
        args = dl.task_args or {}
        task_run_id = args.get("analysis_run_id") or args.get("context", {}).get("analysis_run_id")
        if task_run_id and str(task_run_id) == str(run_uuid):
            target_dl = dl
            review_payload = args.get("review_payload")
            break

    # If not found in dead_letter_log, check Redis fallback (review_payload:{run_id})
    if not review_payload:
        review_payload = get_payload_ref(f"review_payload:{run_uuid}")

    if not review_payload:
        raise HTTPException(
            status_code=404,
            detail=f"No durable review payload found for analysis run {analysis_run_id}",
        )

    # 3. Post to GitHub
    repo = run.repository
    owner, repo_name = repo.full_name.split("/", 1)
    pr_number = run.pull_request_number

    token = None
    settings = get_settings()
    if not settings.mock_github and repo and repo.installation_id:
        try:
            from codepulse.ingestion.diff_fetcher import get_diff_fetcher
            fetcher = get_diff_fetcher()
            token = fetcher.get_installation_token(int(repo.installation_id))
        except Exception as exc:
            logger.warning("Failed to obtain GitHub App installation token for repo %s: %s", repo.full_name, exc)
    poster = get_github_poster(token=token)
    try:
        response = poster.post_review(
            owner=owner,
            repo=repo_name,
            pull_number=pr_number,
            payload=review_payload,
        )
    except Exception as exc:
        logger.error("Admin retry posting failed for %s#%d: %s", repo.full_name, pr_number, exc)
        return JSONResponse(
            status_code=502,
            content={
                "status": "error",
                "message": f"GitHub API review posting failed: {exc}",
                "analysis_run_id": str(run_uuid),
            },
        )

    # 4. Success: update AnalysisRun and mark DeadLetterLog resolved
    review_id = response.get("id")
    now = datetime.now(timezone.utc)

    # Check if this retry is for a follow-up review or primary review
    is_followup = bool(
        run.github_review_id is not None
        or (review_payload and "Follow-up LLM analysis" in review_payload.get("body", ""))
    )

    if is_followup:
        # A follow-up review retry must NEVER overwrite the primary review ID!
        if review_id:
            try:
                from codepulse.persistence.database import get_redis_client
                redis_client = get_redis_client()
                redis_client.set(f"reanalysis:review_id:{run_uuid}", str(review_id), ex=2592000)
            except Exception:
                pass
        # Mark all unposted findings for this run as posted
        unposted = db.query(DBFinding).filter(
            DBFinding.analysis_run_id == run_uuid,
            DBFinding.is_posted == False,
        ).all()
        for f in unposted:
            f.is_posted = True
        run.reanalysis_needed = False
    else:
        # Primary review retry
        run.review_posted_at = now
        if review_id:
            run.github_review_id = review_id
        for f in run.findings:
            f.is_posted = True

    if target_dl:
        target_dl.resolved = True

    db.commit()

    logger.info(
        "Admin retry posting succeeded: review %s for run %s (%s#%d)",
        review_id,
        run_uuid,
        repo.full_name,
        pr_number,
    )
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "github_review_id": review_id,
            "analysis_run_id": str(run_uuid),
            "review_posted_at": now.isoformat(),
        },
    )
