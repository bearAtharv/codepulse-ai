"""FastAPI application assembly for the webhook ingestion service."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from sqlalchemy import text

from codepulse.ingestion.dependencies import get_redis_client
from codepulse.ingestion.webhook import router as webhook_router
from codepulse.persistence.database import get_engine

logger = logging.getLogger(__name__)

app = FastAPI(
    title="CodePulse AI",
    description="AI-powered code review for security vulnerabilities and memory leaks",
    version="0.1.0",
)

app.include_router(webhook_router)


@app.get("/health/live")
async def liveness() -> dict[str, str]:
    """Liveness probe — returns 200 if the process is running (Section 8.5)."""
    return {"status": "alive"}


@app.get("/health/ready")
async def readiness() -> dict:
    """Readiness probe — checks Redis and PostgreSQL connectivity (Section 8.5)."""
    errors: list[str] = []

    try:
        redis_client = get_redis_client()
        redis_client.ping()
    except Exception as exc:
        errors.append(f"Redis: {exc}")

    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        errors.append(f"PostgreSQL: {exc}")

    if errors:
        return {"status": "not ready", "errors": errors}
    return {"status": "ready"}
