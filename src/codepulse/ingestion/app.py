"""FastAPI application assembly for the webhook ingestion service."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from codepulse.persistence.database import get_engine, get_redis_client
from codepulse.ingestion.webhook import router as webhook_router

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
def readiness() -> JSONResponse:
    """Readiness probe — checks Redis and PostgreSQL connectivity (Section 8.5).

    Uses a plain ``def`` (not ``async def``) so that the synchronous
    Redis/Postgres calls run in a threadpool and don't block the event loop.
    Returns HTTP 503 when any dependency is unreachable.
    """
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
        return JSONResponse(
            status_code=503,
            content={"status": "not ready", "errors": errors},
        )
    return JSONResponse(content={"status": "ready"})
