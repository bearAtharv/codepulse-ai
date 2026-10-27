"""Observability, distributed tracing, and structured logging package (§9.3, §9.4, DEC-018)."""

from codepulse.observability.formatter import JSONLogFormatter
from codepulse.observability.redaction import SecretAndCodeSanitizer, sanitize_text
from codepulse.observability.setup import configure_logging
from codepulse.observability.tracing import (
    clear_trace_context,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    get_span_id,
    get_trace_context,
    get_trace_id,
    parse_traceparent,
    set_trace_context,
    trace_scope,
)

__all__ = [
    "JSONLogFormatter",
    "SecretAndCodeSanitizer",
    "clear_trace_context",
    "configure_logging",
    "format_traceparent",
    "generate_span_id",
    "generate_trace_id",
    "get_span_id",
    "get_trace_context",
    "get_trace_id",
    "parse_traceparent",
    "sanitize_text",
    "set_trace_context",
    "trace_scope",
]
