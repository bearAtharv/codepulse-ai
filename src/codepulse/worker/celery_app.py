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

