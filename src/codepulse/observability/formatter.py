"""Structured JSON log formatter for CodePulse AI services (§9.4, DEC-018)."""

from __future__ import annotations

import json
import logging
import os
import traceback
from datetime import datetime, timezone
from typing import Any

from codepulse.observability.redaction import sanitize_text
from codepulse.observability.tracing import get_trace_context


class JSONLogFormatter(logging.Formatter):
    """Formats LogRecord instances into single-line JSON strings."""

    def __init__(self, service_name: str | None = None) -> None:
        super().__init__()
        self.default_service = service_name or os.environ.get("SERVICE_NAME", "codepulse-web")

    def format(self, record: logging.LogRecord) -> str:
        # Format the log message safely
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)

        # Apply redaction to message
        message = sanitize_text(message)

        # Timestamp in ISO 8601 UTC
        now_dt = datetime.fromtimestamp(record.created, timezone.utc)
        iso_timestamp = now_dt.isoformat()

        # Extract tracing context
        ctx = get_trace_context()

        # Priority: record attributes (if passed via extra={...}) > contextvars > fallback
        trace_id = getattr(record, "trace_id", None) or ctx["trace_id"]
        span_id = getattr(record, "span_id", None) or ctx["span_id"]
        analysis_run_id = getattr(record, "analysis_run_id", None) or ctx["analysis_run_id"]
        repository = getattr(record, "repository", None) or ctx["repository"]
        pr_number = getattr(record, "pr_number", None) or ctx["pr_number"]
        head_sha = getattr(record, "head_sha", None) or ctx["head_sha"]
        task_id = getattr(record, "task_id", None) or ctx["task_id"]
        task_name = getattr(record, "task_name", None) or ctx["task_name"]
        service = getattr(record, "service", None) or ctx["service"] or self.default_service

        log_data: dict[str, Any] = {
            "timestamp": iso_timestamp,
            "level": record.levelname,
            "service": service,
            "logger": record.name,
            "message": message,
            "trace_id": trace_id,
            "span_id": span_id,
            "analysis_run_id": analysis_run_id,
            "repository": repository,
            "pr_number": pr_number,
            "task_name": task_name,
            "task_id": task_id,
            "head_sha": head_sha,
        }

        # Include exception traceback if present
        if record.exc_info:
            log_data["exception"] = "".join(traceback.format_exception(*record.exc_info))

        return json.dumps(log_data, default=str)
