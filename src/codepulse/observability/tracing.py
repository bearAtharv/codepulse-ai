"""Distributed tracing context, W3C Trace Context, and OpenTelemetry integration (§9.3, DEC-018)."""

from __future__ import annotations

import contextlib
import logging
import os
import re
import secrets
from contextvars import ContextVar
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, set_span_in_context

from codepulse.observability.redaction import sanitize_text

logger = logging.getLogger(__name__)

# Context variables for tracing metadata across async & sync calls
_current_trace_id: ContextVar[str | None] = ContextVar("current_trace_id", default=None)
_current_span_id: ContextVar[str | None] = ContextVar("current_span_id", default=None)
_current_analysis_run_id: ContextVar[str | None] = ContextVar("current_analysis_run_id", default=None)
_current_repository: ContextVar[str | None] = ContextVar("current_repository", default=None)
_current_pr_number: ContextVar[int | None] = ContextVar("current_pr_number", default=None)
_current_head_sha: ContextVar[str | None] = ContextVar("current_head_sha", default=None)
_current_task_id: ContextVar[str | None] = ContextVar("current_task_id", default=None)
_current_task_name: ContextVar[str | None] = ContextVar("current_task_name", default=None)
_current_service: ContextVar[str] = ContextVar(
    "current_service",
    default=os.environ.get("SERVICE_NAME", "codepulse-web"),
)

# W3C traceparent regex: version-trace_id-parent_id-trace_flags
# e.g., 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
W3C_TRACEPARENT_REGEX = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$",
    re.IGNORECASE,
)

# Strict allowlist of permitted span attribute names (§9.3, privacy requirement)
ALLOWED_SPAN_ATTRIBUTES: frozenset[str] = frozenset({
    "trace_id",
    "span_id",
    "parent_span_id",
    "analysis_run_id",
    "repository",
    "pr_number",
    "head_sha",
    "base_sha",
    "task_id",
    "task_name",
    "service",
    "action",
    "event_type",
    "model",
    "model_id",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "cache_hit",
    "status",
    "status_code",
    "http.status_code",
    "http.method",
    "http.url",
    "http.target",
    "http.host",
    "http.scheme",
    "error",
    "error.type",
    "error.message",
    "findings_count",
    "chunks_count",
    "file_count",
    "duration_ms",
    "circuit_breaker.state",
    "circuit_breaker.failures",
    "phase",
    "reanalysis_needed",
    "installation_id",
})


def sanitize_span_attributes(attrs: dict[str, Any]) -> dict[str, Any]:
    """Filter attributes against ALLOWED_SPAN_ATTRIBUTES and redact sensitive strings."""
    sanitized: dict[str, Any] = {}
    for key, value in attrs.items():
        if key in ALLOWED_SPAN_ATTRIBUTES:
            if isinstance(value, str):
                sanitized[key] = sanitize_text(value)
            elif isinstance(value, (int, float, bool)):
                sanitized[key] = value
            elif value is None:
                continue
    return sanitized


class SafeSpanWrapper:
    """Wrapper around OpenTelemetry trace.Span enforcing the attribute allowlist and sanitization."""

    def __init__(self, raw_span: trace.Span) -> None:
        self._raw_span = raw_span

    def set_attribute(self, key: str, value: Any) -> None:
        if key in ALLOWED_SPAN_ATTRIBUTES and value is not None:
            if isinstance(value, str):
                self._raw_span.set_attribute(key, sanitize_text(value))
            elif isinstance(value, (int, float, bool)):
                self._raw_span.set_attribute(key, value)

    def set_attributes(self, attributes: dict[str, Any]) -> None:
        for k, v in attributes.items():
            self.set_attribute(k, v)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw_span, name)


def is_tracing_enabled() -> bool:
    """Check if distributed tracing is enabled via environment variable."""
    return os.environ.get("OTEL_TRACING_ENABLED", "true").lower() in ("true", "1", "yes")


_tracer_initialized = False


def init_tracing(service_name: str | None = None) -> None:
    """Initialize OpenTelemetry TracerProvider with OTLP HTTP exporter."""
    global _tracer_initialized
    if _tracer_initialized:
        return
    if not is_tracing_enabled():
        return

    srv_name = service_name or os.environ.get("SERVICE_NAME", "codepulse-web")
    resource = Resource.create({"service.name": srv_name})
    provider = TracerProvider(resource=resource)

    raw_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://tempo:4318")
    endpoint = raw_endpoint if raw_endpoint.endswith("/v1/traces") else f"{raw_endpoint.rstrip('/')}/v1/traces"

    try:
        exporter = OTLPSpanExporter(endpoint=endpoint, timeout=2)
        processor = BatchSpanProcessor(
            exporter,
            max_queue_size=2048,
            schedule_delay_millis=200,
            max_export_batch_size=512,
            export_timeout_millis=2000,
        )
        provider.add_span_processor(processor)
    except Exception as exc:
        logger.warning("Could not initialize OTLP span exporter (%s): %s", endpoint, exc)

    trace.set_tracer_provider(provider)
    _tracer_initialized = True


def flush_tracing(timeout_millis: int = 2000) -> None:
    """Force-flush pending spans to the exporter."""
    provider = trace.get_tracer_provider()
    if hasattr(provider, "force_flush"):
        try:
            provider.force_flush(timeout_millis=timeout_millis)
        except Exception:
            pass


def generate_trace_id() -> str:
    """Generate a 16-byte (32 hex characters) W3C-compliant Trace ID."""
    return secrets.token_hex(16).lower()


def generate_span_id() -> str:
    """Generate an 8-byte (16 hex characters) W3C-compliant Span ID."""
    return secrets.token_hex(8).lower()


def format_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    """Format W3C Trace Context traceparent header value."""
    flags = "01" if sampled else "00"
    return f"00-{trace_id.lower()}-{span_id.lower()}-{flags}"


def parse_traceparent(header_value: str | None) -> tuple[str, str] | None:
    """Parse a W3C traceparent header, returning (trace_id, span_id) or None."""
    if not header_value:
        return None
    match = W3C_TRACEPARENT_REGEX.match(header_value.strip())
    if not match:
        return None
    version, trace_id, span_id, _ = match.groups()
    if version == "ff" or trace_id == "0" * 32 or span_id == "0" * 16:
        return None
    return trace_id.lower(), span_id.lower()


def get_trace_id() -> str | None:
    """Retrieve current trace ID from context."""
    return _current_trace_id.get()


def get_span_id() -> str | None:
    """Retrieve current span ID from context."""
    return _current_span_id.get()


def get_trace_context() -> dict[str, Any]:
    """Retrieve all current tracing context attributes."""
    return {
        "trace_id": _current_trace_id.get(),
        "span_id": _current_span_id.get(),
        "analysis_run_id": _current_analysis_run_id.get(),
        "repository": _current_repository.get(),
        "pr_number": _current_pr_number.get(),
        "head_sha": _current_head_sha.get(),
        "task_id": _current_task_id.get(),
        "task_name": _current_task_name.get(),
        "service": _current_service.get(),
    }


def set_trace_context(
    trace_id: str | None = None,
    span_id: str | None = None,
    analysis_run_id: str | None = None,
    repository: str | None = None,
    pr_number: int | None = None,
    head_sha: str | None = None,
    task_id: str | None = None,
    task_name: str | None = None,
    service: str | None = None,
) -> None:
    """Set active trace context variables."""
    if trace_id is not None:
        _current_trace_id.set(trace_id)
    if span_id is not None:
        _current_span_id.set(span_id)
    if analysis_run_id is not None:
        _current_analysis_run_id.set(analysis_run_id)
    if repository is not None:
        _current_repository.set(repository)
    if pr_number is not None:
        _current_pr_number.set(pr_number)
    if head_sha is not None:
        _current_head_sha.set(head_sha)
    if task_id is not None:
        _current_task_id.set(task_id)
    if task_name is not None:
        _current_task_name.set(task_name)
    if service is not None:
        _current_service.set(service)


def clear_trace_context() -> None:
    """Reset trace context to defaults."""
    _current_trace_id.set(None)
    _current_span_id.set(None)
    _current_analysis_run_id.set(None)
    _current_repository.set(None)
    _current_pr_number.set(None)
    _current_head_sha.set(None)
    _current_task_id.set(None)
    _current_task_name.set(None)


@contextlib.contextmanager
def trace_scope(
    trace_id: str | None = None,
    span_id: str | None = None,
    analysis_run_id: str | None = None,
    repository: str | None = None,
    pr_number: int | None = None,
    head_sha: str | None = None,
    task_id: str | None = None,
    task_name: str | None = None,
    service: str | None = None,
) -> Generator[tuple[str, str], None, None]:
    """Context manager for scoping tracing and log attributes."""
    t_id = trace_id or _current_trace_id.get() or generate_trace_id()
    s_id = span_id or generate_span_id()

    token_trace = _current_trace_id.set(t_id)
    token_span = _current_span_id.set(s_id)
    token_run = _current_analysis_run_id.set(analysis_run_id) if analysis_run_id else None
    token_repo = _current_repository.set(repository) if repository else None
    token_pr = _current_pr_number.set(pr_number) if pr_number is not None else None
    token_sha = _current_head_sha.set(head_sha) if head_sha else None
    token_tid = _current_task_id.set(task_id) if task_id else None
    token_tname = _current_task_name.set(task_name) if task_name else None
    token_srv = _current_service.set(service) if service else None

    try:
        yield t_id, s_id
    finally:
        _current_trace_id.reset(token_trace)
        _current_span_id.reset(token_span)
        if token_run:
            _current_analysis_run_id.reset(token_run)
        if token_repo:
            _current_repository.reset(token_repo)
        if token_pr:
            _current_pr_number.reset(token_pr)
        if token_sha:
            _current_head_sha.reset(token_sha)
        if token_tid:
            _current_task_id.reset(token_tid)
        if token_tname:
            _current_task_name.reset(token_tname)
        if token_srv:
            _current_service.reset(token_srv)


@contextlib.contextmanager
def trace_span(
    name: str,
    attributes: dict[str, Any] | None = None,
    trace_id: str | None = None,
    parent_span_id: str | None = None,
    service: str | None = None,
) -> Generator[SafeSpanWrapper, None, None]:
    """Context manager that starts an OpenTelemetry span with correlation and allowlisted attributes."""
    t_id = trace_id or _current_trace_id.get() or generate_trace_id()
    p_id = parent_span_id or _current_span_id.get()

    tracer = trace.get_tracer("codepulse")
    otel_parent_ctx = None
    if t_id and p_id:
        try:
            parent_sc = SpanContext(
                trace_id=int(t_id, 16),
                span_id=int(p_id, 16),
                is_remote=True,
                trace_flags=TraceFlags(0x01),
            )
            otel_parent_ctx = set_span_in_context(NonRecordingSpan(parent_sc))
        except ValueError:
            otel_parent_ctx = None
    elif t_id:
        try:
            parent_sc = SpanContext(
                trace_id=int(t_id, 16),
                span_id=int(t_id[:16], 16),
                is_remote=True,
                trace_flags=TraceFlags(0x01),
            )
            otel_parent_ctx = set_span_in_context(NonRecordingSpan(parent_sc))
        except ValueError:
            otel_parent_ctx = None

    with tracer.start_as_current_span(name, context=otel_parent_ctx) as raw_span:
        s_ctx = raw_span.get_span_context()
        cur_t_id = format(s_ctx.trace_id, "032x") if s_ctx.trace_id else t_id
        cur_s_id = format(s_ctx.span_id, "016x") if s_ctx.span_id else generate_span_id()

        wrapper = SafeSpanWrapper(raw_span)

        # Baseline safe attributes
        base_attrs: dict[str, Any] = {
            "trace_id": cur_t_id,
            "span_id": cur_s_id,
        }
        if p_id:
            base_attrs["parent_span_id"] = p_id
        if _current_repository.get():
            base_attrs["repository"] = _current_repository.get()
        if _current_pr_number.get() is not None:
            base_attrs["pr_number"] = _current_pr_number.get()
        if _current_head_sha.get():
            base_attrs["head_sha"] = _current_head_sha.get()
        if _current_analysis_run_id.get():
            base_attrs["analysis_run_id"] = _current_analysis_run_id.get()
        if _current_task_id.get():
            base_attrs["task_id"] = _current_task_id.get()
        if _current_task_name.get():
            base_attrs["task_name"] = _current_task_name.get()
        if service:
            base_attrs["service"] = service
        elif _current_service.get():
            base_attrs["service"] = _current_service.get()

        if attributes:
            base_attrs.update(attributes)

        wrapper.set_attributes(base_attrs)

        # Set context variables for logs emitted during this span
        token_t = _current_trace_id.set(cur_t_id)
        token_s = _current_span_id.set(cur_s_id)
        token_srv = _current_service.set(service) if service else None

        try:
            yield wrapper
        finally:
            _current_trace_id.reset(token_t)
            _current_span_id.reset(token_s)
            if token_srv:
                _current_service.reset(token_srv)
