"""FastAPI application assembly for the webhook ingestion service."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from codepulse.observability import (
    configure_logging,
    flush_tracing,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    get_span_id,
    get_trace_id,
    init_tracing,
    parse_traceparent,
    trace_scope,
    trace_span,
)
from codepulse.config import get_settings, validate_settings
from codepulse.metrics.server import start_metrics_server
from codepulse.persistence.database import get_engine, get_redis_client
from fastapi.staticfiles import StaticFiles
from codepulse.ingestion.admin import router as admin_router
from codepulse.ingestion.webhook import router as webhook_router
from codepulse.ui.router import STATIC_DIR, router as ui_router

# Initialize structured logging (§9.4, DEC-018)
configure_logging(service_name="codepulse-web")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start internal metrics server on isolated port 9090 and validate configuration."""
    import sys
    validate_settings(get_settings())
    init_tracing(service_name="codepulse-web")
    metrics_port = int(os.environ.get("METRICS_PORT", "9090"))
    metrics_server = None
    if os.environ.get("TEST_ENV", "").lower() not in ("true", "1") and "pytest" not in sys.modules:
        try:
            metrics_server = start_metrics_server(port=metrics_port)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Could not start internal metrics server: %s", exc)
    yield
    flush_tracing()
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


@app.middleware("http")
async def trace_id_middleware(request: Request, call_next):
    """Propagate or generate W3C trace ID and set X-Trace-Id header (§9.3)."""
    traceparent = request.headers.get("traceparent")
    parsed_tp = parse_traceparent(traceparent) if traceparent else None
    if parsed_tp:
        trace_id, parent_span_id = parsed_tp
    else:
        trace_id = request.headers.get("X-Trace-Id") or generate_trace_id()
        parent_span_id = None

    span_name = "http.webhook_receive" if request.url.path.startswith("/webhooks") else f"http.{request.method.lower()}"
    with trace_span(
        span_name,
        trace_id=trace_id,
        parent_span_id=parent_span_id,
        service="codepulse-web",
        attributes={"http.method": request.method, "http.target": request.url.path},
    ) as span:
        response = await call_next(request)
        span.set_attribute("http.status_code", response.status_code)
        active_t = get_trace_id() or trace_id
        active_s = get_span_id()
        response.headers["X-Trace-Id"] = active_t
        if active_s:
            response.headers["traceparent"] = format_traceparent(active_t, active_s)
        return response


app.include_router(webhook_router)
app.include_router(admin_router)
app.include_router(ui_router)
app.mount("/ui/static", StaticFiles(directory=str(STATIC_DIR)), name="ui_static")


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
