"""Celery application configuration.

Configures queues, task routing, serializer, and Redis broker/result backend
for the CodePulse worker pipeline (Section 3.5).
"""

from __future__ import annotations

from celery import Celery

from codepulse.config import get_settings

settings = get_settings()

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
    task_routes={
        "tasks.orchestrate_pr_analysis": {"queue": "cp-high"},
        "tasks.fetch_pr_diff": {"queue": "cp-high"},
        "tasks.post_review_to_github": {"queue": "cp-high"},
        "tasks.analyze_ast": {"queue": "cp-analysis"},
        "tasks.analyze_llm": {"queue": "cp-analysis"},
        "tasks.preprocess_and_chunk": {"queue": "cp-aggregate"},
        "tasks.aggregate_findings": {"queue": "cp-aggregate"},
        "tasks.persist_results": {"queue": "cp-aggregate"},
    },
)
