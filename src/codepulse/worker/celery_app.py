"""Celery application configuration.

Configures queues, task routing, serializer, and Redis broker/result backend
for the CodePulse worker pipeline (Section 3.5).
"""

from __future__ import annotations

import os
from typing import Any

import celery.app.trace
from celery import Celery

from codepulse.config import get_settings

# Prevent Celery trace from logging return_value payloads (source code, diffs, findings)
celery.app.trace.LOG_SUCCESS = "Task %(name)s[%(id)s] succeeded in %(runtime)ss"

settings = get_settings()

# Ensure multiprocess metrics directory exists early if specified
_multiproc_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
if _multiproc_dir:
    os.makedirs(_multiproc_dir, exist_ok=True)

celery_app = Celery(
    "codepulse",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["codepulse.worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_queue="cp-high",
    broker_transport_options={"visibility_timeout": 300},
    task_annotations={
        "tasks.fetch_pr_diff": {"soft_time_limit": 30, "time_limit": 45},
        "tasks.preprocess_and_chunk": {"soft_time_limit": 10, "time_limit": 15},
        "tasks.analyze_ast": {"soft_time_limit": 5, "time_limit": 8},
        "tasks.analyze_llm": {"soft_time_limit": 15, "time_limit": 20},
        "tasks.aggregate_findings": {"soft_time_limit": 5, "time_limit": 8},
        "tasks.post_review_to_github": {"soft_time_limit": 30, "time_limit": 45},
        "tasks.persist_results": {"soft_time_limit": 10, "time_limit": 15},
    },
    task_routes={
        "tasks.orchestrate_pr_analysis": {"queue": "cp-high"},
        "tasks.fetch_pr_diff": {"queue": "cp-high"},
        "tasks.post_review_to_github": {"queue": "cp-high"},
        "tasks.scan_reanalysis_needed": {"queue": "cp-high"},
        "tasks.drain_pending_persistence_task": {"queue": "cp-high"},
        "tasks.analyze_ast": {"queue": "cp-analysis"},
        "tasks.analyze_llm": {"queue": "cp-analysis"},
        "tasks.preprocess_and_chunk": {"queue": "cp-aggregate"},
        "tasks.aggregate_findings": {"queue": "cp-aggregate"},
        "tasks.persist_results": {"queue": "cp-aggregate"},
    },
    beat_schedule={
        "scan-reanalysis-needed": {
            "task": "tasks.scan_reanalysis_needed",
            "schedule": 300.0,  # every 5 minutes (§6.4)
            "options": {"queue": "cp-high"},
        },
        "drain-pending-persistence": {
            "task": "tasks.drain_pending_persistence_task",
            "schedule": 60.0,  # every 60 seconds (judgment call)
            "options": {"queue": "cp-high"},
        },
    },
)

# ── Metrics server for worker processes (§9.2, DEC-016) ─────────────
from celery.signals import worker_init, worker_ready


@worker_init.connect
def on_worker_init(**kwargs: Any) -> None:
    """Ensure multiprocess metrics directory exists."""
    import os
    multiproc_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if multiproc_dir:
        os.makedirs(multiproc_dir, exist_ok=True)


@worker_ready.connect
def on_worker_ready(**kwargs: Any) -> None:
    """Start internal metrics server on port 9091 in main worker process."""
    import logging
    import os
    from codepulse.metrics.server import start_metrics_server

    port = int(os.environ.get("WORKER_METRICS_PORT", "9091"))
    try:
        start_metrics_server(port=port)
    except Exception as exc:
        logging.getLogger(__name__).warning("Could not start worker metrics server on port %d: %s", port, exc)


# ── Structured Logging & Trace Context Propagation (§9.3, §9.4, DEC-018) ─────
from celery.signals import setup_logging, task_prerun, task_postrun
from codepulse.observability import (
    configure_logging,
    generate_span_id,
    generate_trace_id,
    set_trace_context,
    clear_trace_context,
)


@setup_logging.connect
def on_setup_logging(**kwargs: Any) -> None:
    """Configure Celery worker to use structured JSON logging."""
    service_name = os.environ.get("SERVICE_NAME", "codepulse-worker")
    configure_logging(service_name=service_name)


@task_prerun.connect
def on_task_prerun(
    sender: Any = None,
    task_id: str | None = None,
    task: Any = None,
    args: tuple | None = None,
    kwargs: dict | None = None,
    **extra: Any,
) -> None:
    """Extract and establish trace context for executing Celery task."""
    headers = getattr(task.request, "headers", {}) or {}
    trace_id = headers.get("trace_id")
    span_id = headers.get("span_id") or generate_span_id()

    # Fallback to kwargs or args inspection
    if not trace_id and kwargs:
        trace_id = kwargs.get("trace_id")
        if not trace_id and "payload" in kwargs and isinstance(kwargs["payload"], dict):
            trace_id = kwargs["payload"].get("trace_id")
        if not trace_id and "context" in kwargs and isinstance(kwargs["context"], dict):
            trace_id = kwargs["context"].get("trace_id")
    if not trace_id and args:
        for arg in args:
            if isinstance(arg, dict):
                trace_id = arg.get("trace_id")
                if not trace_id and isinstance(arg.get("context"), dict):
                    trace_id = arg["context"].get("trace_id")
                if trace_id:
                    break

    trace_id = trace_id or generate_trace_id()

    # Extract metadata
    repo = None
    pr = None
    sha = None
    run_id = None
    if kwargs:
        repo = kwargs.get("repository_full_name")
        pr = kwargs.get("pull_request_number")
        sha = kwargs.get("head_sha")
        run_id = kwargs.get("analysis_run_id")
    if args and isinstance(args[0], dict):
        d = args[0]
        ctx = d.get("context") if isinstance(d.get("context"), dict) else d
        repo = repo or ctx.get("repository_full_name")
        pr = pr or ctx.get("pull_request_number")
        sha = sha or ctx.get("head_sha")
        run_id = run_id or ctx.get("analysis_run_id")

    task_name = getattr(task, "name", str(sender))
    service_name = os.environ.get("SERVICE_NAME", "codepulse-worker")

    set_trace_context(
        trace_id=trace_id,
        span_id=span_id,
        task_id=task_id,
        task_name=task_name,
        repository=repo,
        pr_number=int(pr) if pr is not None else None,
        head_sha=sha,
        analysis_run_id=str(run_id) if run_id else None,
        service=service_name,
    )


@task_postrun.connect
def on_task_postrun(sender: Any = None, task_id: str | None = None, task: Any = None, **extra: Any) -> None:
    """Clear trace context after task execution."""
    clear_trace_context()


