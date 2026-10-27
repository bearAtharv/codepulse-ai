"""Logging configuration and initialization for services (§9.4, DEC-018)."""

from __future__ import annotations

import logging
import os
import sys

from codepulse.observability.formatter import JSONLogFormatter
from codepulse.observability.redaction import SecretAndCodeSanitizer


def configure_logging(service_name: str | None = None, level: str | None = None) -> None:
    """Configure root and application loggers for structured JSON output."""
    raw_level = level or os.environ.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, raw_level, logging.INFO)
    srv_name = service_name or os.environ.get("SERVICE_NAME", "codepulse-web")

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(JSONLogFormatter(service_name=srv_name))
    stream_handler.addFilter(SecretAndCodeSanitizer())

    root_logger.addHandler(stream_handler)

    # Configure uvicorn loggers if running in web service
    for uvicorn_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        u_log = logging.getLogger(uvicorn_name)
        u_log.handlers = []
        u_log.propagate = True

    # Configure celery loggers if running in worker
    for celery_name in ("celery", "celery.task", "celery.worker"):
        c_log = logging.getLogger(celery_name)
        c_log.handlers = []
        c_log.propagate = True
