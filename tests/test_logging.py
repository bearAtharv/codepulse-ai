"""Unit tests for structured JSON logging, W3C distributed tracing, and redaction (§9.3, §9.4, DEC-018)."""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from codepulse.ingestion.app import app
from codepulse.observability import (
    JSONLogFormatter,
    SecretAndCodeSanitizer,
    clear_trace_context,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    get_span_id,
    get_trace_context,
    get_trace_id,
    parse_traceparent,
    sanitize_text,
    set_trace_context,
    trace_scope,
)


class TestW3CTracing:
    """Verification of W3C Trace Context specifications (§9.3)."""

    def test_generate_trace_id_format(self) -> None:
        """Trace ID must be exactly 32 lowercase hexadecimal characters (16 bytes)."""
        trace_id = generate_trace_id()
        assert len(trace_id) == 32
        assert re.fullmatch(r"^[0-9a-f]{32}$", trace_id) is not None

    def test_generate_span_id_format(self) -> None:
        """Span ID must be exactly 16 lowercase hexadecimal characters (8 bytes)."""
        span_id = generate_span_id()
        assert len(span_id) == 16
        assert re.fullmatch(r"^[0-9a-f]{16}$", span_id) is not None

    def test_format_and_parse_traceparent(self) -> None:
        """format_traceparent and parse_traceparent must roundtrip cleanly."""
        t_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        s_id = "00f067aa0ba902b7"
        header = format_traceparent(t_id, s_id, sampled=True)
        assert header == "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

        parsed = parse_traceparent(header)
        assert parsed == (t_id, s_id)

    def test_parse_invalid_traceparent_returns_none(self) -> None:
        """Invalid traceparent strings must return None without raising."""
        assert parse_traceparent(None) is None
        assert parse_traceparent("") is None
        assert parse_traceparent("invalid") is None
        # All-zero trace ID is invalid per W3C spec
        assert parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01") is None

    def test_trace_scope_manages_contextvars(self) -> None:
        """trace_scope sets context on entry and cleans up on exit."""
        clear_trace_context()
        assert get_trace_id() is None

        test_trace = "a" * 32
        test_span = "b" * 16

        with trace_scope(
            trace_id=test_trace,
            span_id=test_span,
            repository="owner/repo",
            pr_number=42,
            analysis_run_id="run-123",
            service="codepulse-web",
        ) as (tid, sid):
            assert tid == test_trace
            assert sid == test_span
            ctx = get_trace_context()
            assert ctx["trace_id"] == test_trace
            assert ctx["span_id"] == test_span
            assert ctx["repository"] == "owner/repo"
            assert ctx["pr_number"] == 42
            assert ctx["analysis_run_id"] == "run-123"
            assert ctx["service"] == "codepulse-web"

        # Context reverts
        assert get_trace_id() is None


class TestStructuredJSONFormatter:
    """Verification of structured JSON log formatting (§9.4)."""

    def test_formatter_produces_valid_json_with_all_mandatory_fields(self) -> None:
        """Log record must format as single-line JSON containing all required §9.4 fields."""
        formatter = JSONLogFormatter(service_name="codepulse-worker")

        record = logging.LogRecord(
            name="codepulse.worker.tasks",
            level=logging.INFO,
            pathname="tasks.py",
            lineno=100,
            msg="Task completed successfully for %s",
            args=("owner/repo",),
            exc_info=None,
        )
        record.created = 1700000000.123

        with trace_scope(
            trace_id="1234567890abcdef1234567890abcdef",
            span_id="abcdef1234567890",
            analysis_run_id="run-uuid-456",
            repository="owner/repo",
            pr_number=99,
            task_name="tasks.analyze_llm",
            service="codepulse-worker",
        ):
            output = formatter.format(record)

        data = json.loads(output)
        mandatory_keys = {
            "timestamp",
            "level",
            "service",
            "trace_id",
            "span_id",
            "analysis_run_id",
            "repository",
            "pr_number",
            "task_name",
            "message",
        }
        for key in mandatory_keys:
            assert key in data, f"Missing mandatory field '{key}' in log entry"

        assert data["level"] == "INFO"
        assert data["service"] == "codepulse-worker"
        assert data["trace_id"] == "1234567890abcdef1234567890abcdef"
        assert data["span_id"] == "abcdef1234567890"
        assert data["analysis_run_id"] == "run-uuid-456"
        assert data["repository"] == "owner/repo"
        assert data["pr_number"] == 99
        assert data["task_name"] == "tasks.analyze_llm"
        assert "owner/repo" in data["message"]

    def test_formatter_includes_exception_traceback(self) -> None:
        """When exc_info is present, formatted output includes the traceback."""
        formatter = JSONLogFormatter(service_name="codepulse-web")
        try:
            raise ValueError("Test error for traceback")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Exception occurred",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "ValueError: Test error for traceback" in data["exception"]


class TestSensitiveDataRedaction:
    """Verification that tokens, secrets, passwords, and diffs are redacted (§9.4)."""

    def test_redacts_gemini_api_key(self) -> None:
        """Gemini AIza API keys must be replaced with [REDACTED_GEMINI_KEY]."""
        raw = "Calling Gemini API with key AIzaSyD9exampleKey1234567890abcdef_12"
        sanitized = sanitize_text(raw)
        assert "AIzaSyD9exampleKey" not in sanitized
        assert "[REDACTED_GEMINI_KEY]" in sanitized

    def test_redacts_github_tokens(self) -> None:
        """GitHub personal access tokens must be replaced with redaction markers."""
        classic_pat = "Authorization: token ghp_1234567890abcdefghijklmnopqrstuvwx"
        fine_grained = "Using github_pat_11AEXAMPLE01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
        assert "[REDACTED_GITHUB_TOKEN]" in sanitize_text(classic_pat)
        assert "[REDACTED_GITHUB_PAT]" in sanitize_text(fine_grained)

    def test_redacts_bearer_tokens(self) -> None:
        """Bearer tokens in headers must be masked."""
        raw = "Headers: {'Authorization': 'Bearer ya29.a0AfH6SM...secret_token...'}"
        sanitized = sanitize_text(raw)
        assert "ya29" not in sanitized
        assert "Bearer [REDACTED_BEARER_TOKEN]" in sanitized

    def test_redacts_database_password_in_urls(self) -> None:
        """Passwords in database URLs must be masked."""
        raw = "Connecting to postgresql://codepulse_user:super_secret_pw_123@db-host:5432/codepulse"
        sanitized = sanitize_text(raw)
        assert "super_secret_pw_123" not in sanitized
        assert "postgresql://codepulse_user:[REDACTED_PASSWORD]@db-host:5432/codepulse" in sanitized

    def test_redacts_unified_diff_patches(self) -> None:
        """Unified diff hunks and file diffs must be replaced with redaction markers."""
        diff_hunk = "Failed parsing hunk:\n@@ -10,6 +10,7 @@ def sensitive_logic():\n+    run_secret()"
        sanitized = sanitize_text(diff_hunk)
        assert "run_secret" not in sanitized
        assert "[REDACTED_DIFF_HUNK]" in sanitized

    def test_logging_filter_sanitizes_record_in_place(self) -> None:
        """SecretAndCodeSanitizer modifies log record msg and args."""
        filt = SecretAndCodeSanitizer()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="User token: %s",
            args=("ghp_1234567890abcdefghijklmnopqrstuvwx",),
            exc_info=None,
        )
        filt.filter(record)
        assert "[REDACTED_GITHUB_TOKEN]" in record.args[0]


class TestHTTPTraceIdPropagation:
    """Verification of HTTP trace ID header propagation (§9.3)."""

    def test_health_endpoint_returns_x_trace_id_header(self) -> None:
        """All HTTP responses must carry an X-Trace-Id header."""
        client = TestClient(app)
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert "X-Trace-Id" in resp.headers
        trace_id = resp.headers["X-Trace-Id"]
        assert len(trace_id) == 32
        assert re.fullmatch(r"^[0-9a-f]{32}$", trace_id) is not None

    def test_incoming_traceparent_is_preserved_in_x_trace_id(self) -> None:
        """If incoming request provides W3C traceparent, its trace_id is preserved."""
        client = TestClient(app)
        incoming_trace = "4bf92f3577b34da6a3ce929d0e0e4736"
        incoming_span = "00f067aa0ba902b7"
        traceparent = f"00-{incoming_trace}-{incoming_span}-01"

        resp = client.get("/health/live", headers={"traceparent": traceparent})
        assert resp.status_code == 200
        assert resp.headers["X-Trace-Id"] == incoming_trace
