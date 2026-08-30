"""Celery application configuration.

The Celery app is created at module level so that tasks can be registered
via ``@celery_app.task``.  The broker connection is lazy — Celery only
connects when a task is actually sent or a worker starts.
"""

from celery import Celery

from codepulse.config import get_settings

settings = get_settings()

celery_app = Celery(
    "codepulse",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
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
)
