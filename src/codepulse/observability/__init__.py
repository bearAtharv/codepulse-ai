"""Observability, distributed tracing, and structured logging package (§9.3, §9.4, DEC-018)."""

from codepulse.observability.formatter import JSONLogFormatter
from codepulse.observability.redaction import SecretAndCodeSanitizer, sanitize_text
from codepulse.observability.setup import configure_logging
from codepulse.observability.tracing import (
    ALLOWED_SPAN_ATTRIBUTES,
    SafeSpanWrapper,
    clear_trace_context,
    flush_tracing,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    get_span_id,
    get_trace_context,
    get_trace_id,
    init_tracing,
    is_tracing_enabled,
    parse_traceparent,
    sanitize_span_attributes,
    set_trace_context,
    trace_scope,
    trace_span,
)

__all__ = [
    "ALLOWED_SPAN_ATTRIBUTES",
    "JSONLogFormatter",
    "SafeSpanWrapper",
    "SecretAndCodeSanitizer",
    "clear_trace_context",
    "configure_logging",
    "flush_tracing",
    "format_traceparent",
    "generate_span_id",
    "generate_trace_id",
    "get_span_id",
    "get_trace_context",
    "get_trace_id",
    "init_tracing",
    "is_tracing_enabled",
    "parse_traceparent",
    "sanitize_span_attributes",
    "sanitize_text",
    "set_trace_context",
    "trace_scope",
    "trace_span",
]
