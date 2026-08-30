"""Webhook endpoint — GitHub PR event handler (Section 3.1)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import redis as redis_lib
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from codepulse.config import Settings
from codepulse.ingestion import service
from codepulse.ingestion.dependencies import (
    get_db_session,
    get_redis_client,
    get_settings_dep,
)
from codepulse.ingestion.signature import verify_webhook_signature
from codepulse.worker.tasks import orchestrate_pr_analysis

logger = logging.getLogger(__name__)

router = APIRouter()

# Accepted pull_request actions per Section 3.1.2
ACCEPTED_PR_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


@router.post("/webhooks")
async def handle_webhook(
    request: Request,
    redis_client: redis_lib.Redis = Depends(get_redis_client),
    db: Session = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dep),
) -> Response:
    """Receive and process GitHub webhook events.

    Flow (mirrors Section 10.1, Steps 1-7):

    1. Read raw body, verify HMAC-SHA256 signature → 401 on failure
    2. Parse JSON, extract event type and action
    3. Handle ping → 200 ``{"status": "pong"}``
    4. Filter by event type / action → 200 for unhandled events
    5. Idempotency check via Redis ``SET NX`` → 200 for duplicates
    6. Upsert repository, create ``analysis_runs`` row
    7. Enqueue Celery task → 202
    """
    # ── Step 1: Read body + verify signature ─────────────────────────────
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not verify_webhook_signature(body, signature, settings.github_webhook_secret):
        logger.warning(
            "Invalid webhook signature from %s, delivery=%s",
            request.client.host if request.client else "unknown",
            request.headers.get("X-GitHub-Delivery", "unknown"),
        )
        raise HTTPException(status_code=401, detail="Invalid signature")

    # ── Step 2: Parse JSON ───────────────────────────────────────────────
    payload: dict = json.loads(body)
    event_type: str = request.headers.get("X-GitHub-Event", "")
    delivery_id: str = request.headers.get("X-GitHub-Delivery", "")
    action: str | None = payload.get("action")
    repo_full_name: str | None = (payload.get("repository") or {}).get("full_name")

    # ── Step 3: Handle ping ──────────────────────────────────────────────
    if event_type == "ping":
        service.log_webhook_event(
            db, delivery_id, event_type, action, repo_full_name, processed=True
        )
        return Response(
            content=json.dumps({"status": "pong"}),
            status_code=200,
            media_type="application/json",
        )

    # ── Step 3b: Filter events ───────────────────────────────────────────
    if event_type != "pull_request" or action not in ACCEPTED_PR_ACTIONS:
        logger.debug("Filtered event: type=%s action=%s", event_type, action)
        service.log_webhook_event(db, delivery_id, event_type, action, repo_full_name)
        return Response(status_code=200)

    # ── Step 4: Extract PR data + Idempotency check (Redis SET NX) ──────
    pr: dict = payload["pull_request"]
    installation_id: int = payload["installation"]["id"]
    head_sha: str = pr["head"]["sha"]
    base_sha: str = pr["base"]["sha"]
    pr_number: int = pr["number"]
    pr_author: str = pr["user"]["login"]

    idempotency_key = f"idempotency:{installation_id}:{pr_number}:{head_sha}"
    is_new = redis_client.set(
        idempotency_key, "1", nx=True, ex=settings.idempotency_ttl
    )

    if not is_new:
        logger.info("Duplicate webhook: %s", idempotency_key)
        service.log_webhook_event(
            db, delivery_id, event_type, action, repo_full_name, duplicate=True
        )
        return Response(status_code=200)

    # ── Step 5: Upsert repository + create analysis run ──────────────────
    webhook_received_at = datetime.now(timezone.utc).isoformat()

    repo_id = service.upsert_repository(db, payload["repository"], installation_id)

    run_id = service.create_analysis_run(
        db, repo_id, pr_number, head_sha, base_sha, pr_author, webhook_received_at
    )
    if run_id is None:
        # DB-level idempotency fallback caught a duplicate
        logger.info(
            "DB-level duplicate for %s#%d@%s", repo_full_name, pr_number, head_sha[:8]
        )
        service.log_webhook_event(
            db, delivery_id, event_type, action, repo_full_name, duplicate=True
        )
        return Response(status_code=200)

    # ── Step 6: Enqueue Celery task ──────────────────────────────────────
    orchestrate_pr_analysis.apply_async(
        kwargs={
            "installation_id": installation_id,
            "repository_full_name": repo_full_name,
            "pull_request_number": pr_number,
            "head_sha": head_sha,
            "base_sha": base_sha,
            "pr_author": pr_author,
            "webhook_received_at": webhook_received_at,
            "analysis_run_id": str(run_id),
        },
        queue="cp-high",
    )
    logger.info(
        "Enqueued analysis: repo=%s pr=#%d sha=%s run=%s",
        repo_full_name,
        pr_number,
        head_sha[:8],
        run_id,
    )

    # ── Step 7: Log and return 202 ───────────────────────────────────────
    service.log_webhook_event(
        db, delivery_id, event_type, action, repo_full_name, processed=True
    )
    return Response(status_code=202)
