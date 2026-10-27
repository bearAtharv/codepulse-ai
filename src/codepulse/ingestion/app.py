"""FastAPI application assembly for the webhook ingestion service."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from codepulse.metrics.server import start_metrics_server
from codepulse.persistence.database import get_engine, get_redis_client
from codepulse.ingestion.admin import router as admin_router
from codepulse.ingestion.webhook import router as webhook_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start internal metrics server on isolated port 9090."""
    import sys
    metrics_port = int(os.environ.get("METRICS_PORT", "9090"))
    metrics_server = None
    if os.environ.get("TEST_ENV", "").lower() not in ("true", "1") and "pytest" not in sys.modules:
        try:
            metrics_server = start_metrics_server(port=metrics_port)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Could not start internal metrics server: %s", exc)
    yield
    if metrics_server:
        try:
            metrics_server.shutdown()
        except Exception:
            pass


app = FastAPI(
    title="CodePulse AI",
    description="AI-powered code review for security vulnerabilities and memory leaks",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(webhook_router)
app.include_router(admin_router)


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
