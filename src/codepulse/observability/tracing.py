"""Distributed tracing context and W3C Trace Context utilities (§9.3, DEC-018)."""

from __future__ import annotations

import contextlib
import os
import re
import secrets
from contextvars import ContextVar
from typing import Any, Generator

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
