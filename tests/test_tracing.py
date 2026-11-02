"""Tests for OpenTelemetry distributed tracing and attribute security (§9.3, DEC-018)."""

from __future__ import annotations

import os
import pytest
from unittest.mock import MagicMock

from codepulse.observability.tracing import (
    ALLOWED_SPAN_ATTRIBUTES,
    SafeSpanWrapper,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    get_span_id,
    get_trace_id,
    parse_traceparent,
    sanitize_span_attributes,
    set_trace_context,
    trace_scope,
    trace_span,
)


def test_w3c_traceparent_formatting_and_parsing() -> None:
    """W3C traceparent header formatting and parsing roundtrip."""
    t_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    s_id = "00f067aa0ba902b7"
    header = format_traceparent(t_id, s_id, sampled=True)
    assert header == "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

    parsed = parse_traceparent(header)
    assert parsed == (t_id, s_id)

    # Invalid cases
    assert parse_traceparent(None) is None
    assert parse_traceparent("invalid") is None
    assert parse_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") is None
    assert parse_traceparent(f"00-{'0'*32}-00f067aa0ba902b7-01") is None


def test_span_attributes_allowlist_drops_forbidden_data() -> None:
    """Ensure source code, diffs, review text, tokens, and secrets are strictly excluded."""
    candidate_attrs = {
        # Forbidden items: source code, diffs, reviews, secrets
        "source_code": "def secret_function(): pass",
        "diff": "diff --git a/app.py b/app.py\n@@ -1 +1 @@",
        "patch": "@@ -1,2 +1,2 @@",
        "review_body": "This code contains a security flaw on line 42",
        "comments": [{"line": 1, "body": "fix this"}],
        "github_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "secret_key": "AQ.secret1234567890",
        "password": "supersecretpassword",
        "db_password": "postgres_password",
        "code_snippet": "eval(user_input)",
        # Allowed items
        "repository": "corp/security-service",
        "pr_number": 42,
        "head_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "task_name": "tasks.analyze_llm",
        "model": "gemini-3.7-flash",
        "prompt_tokens": 120,
        "completion_tokens": 45,
        "http.status_code": 200,
        "status": "completed",
        "error.message": "Request failed with key AIzaSyFakeTokenValue123456789",
    }

    sanitized = sanitize_span_attributes(candidate_attrs)

    # Verify forbidden attributes are completely absent
    forbidden_keys = [
        "source_code",
        "diff",
        "patch",
        "review_body",
        "comments",
        "github_token",
        "secret_key",
        "password",
        "db_password",
        "code_snippet",
    ]
    for key in forbidden_keys:
        assert key not in sanitized, f"Forbidden attribute {key} was not filtered out"

    # Verify allowed attributes are preserved
    assert sanitized["repository"] == "corp/security-service"
    assert sanitized["pr_number"] == 42
    assert sanitized["task_name"] == "tasks.analyze_llm"
    assert sanitized["model"] == "gemini-3.7-flash"
    assert sanitized["prompt_tokens"] == 120
    assert sanitized["completion_tokens"] == 45
    assert sanitized["http.status_code"] == 200

    # Verify sensitive data within allowed attributes is redacted
    assert "[REDACTED_GEMINI_KEY]" in sanitized["error.message"]
    assert "AIzaSyFakeTokenValue123456789" not in sanitized["error.message"]


def test_safe_span_wrapper_enforces_allowlist() -> None:
    """SafeSpanWrapper prevents setting forbidden attributes directly on spans."""
    raw_span = MagicMock()
    wrapper = SafeSpanWrapper(raw_span)

    # Attempt to set forbidden attributes
    wrapper.set_attribute("diff", "@@ -1,3 +1,3 @@")
    wrapper.set_attribute("token", "ghp_1234567890abcdef")
    wrapper.set_attribute("user_source", "import os; os.system('ls')")
    assert raw_span.set_attribute.call_count == 0

    # Set allowed attribute
    wrapper.set_attribute("repository", "corp/repo")
    raw_span.set_attribute.assert_called_once_with("repository", "corp/repo")

    # Set batch attributes with mixed keys
    raw_span.reset_mock()
    wrapper.set_attributes({
        "pr_number": 99,
        "raw_code": "print('hello')",
        "findings_count": 3,
        "error.message": "Access token ghs_testinstallationtoken123 expired",
    })
    called_keys = [call[0][0] for call in raw_span.set_attribute.call_args_list]
    assert "pr_number" in called_keys
    assert "findings_count" in called_keys
    assert "error.message" in called_keys
    assert "raw_code" not in called_keys

    # Check redaction inside error.message
    for call in raw_span.set_attribute.call_args_list:
        if call[0][0] == "error.message":
            assert "[REDACTED_GITHUB_INSTALLATION_TOKEN]" in call[0][1]


def test_trace_span_context_nesting_and_correlation() -> None:
    """trace_span context manager correctly sets and restores context vars."""
    t_id = "1234567890abcdef1234567890abcdef"
    p_id = "fedcba0987654321"

    set_trace_context(trace_id=t_id, span_id=p_id, repository="corp/repo", pr_number=10)

    with trace_span("celery.task", attributes={"task_name": "tasks.fetch_pr_diff"}) as span:
        current_t = get_trace_id()
        current_s = get_span_id()
        assert current_t == t_id
        # Child span has a newly generated span ID
        assert current_s is not None

        # Nested span for outbound API call
        with trace_span("github.fetch_diff") as child_span:
            assert get_trace_id() == t_id
            assert get_span_id() is not None

        # Back in task span
        assert get_span_id() == current_s


def test_dynamic_unallowlisted_attributes_are_never_emitted() -> None:
    """Verify that ANY dynamic, arbitrary, or unknown key outside ALLOWED_SPAN_ATTRIBUTES is rejected."""
    raw_span = MagicMock()
    wrapper = SafeSpanWrapper(raw_span)

    # Generate 50 dynamic unallowlisted attributes
    dynamic_forbidden = {
        f"arbitrary_user_key_{i}": f"secret_value_{i}"
        for i in range(25)
    }
    # Add variations containing substrings of sensitive terms
    dynamic_forbidden.update({
        "customer_diff": "diff --git a/test b/test",
        "raw_source_blob": "SELECT * FROM users WHERE id = '%s'",
        "bearer_token_val": "ghp_xxxxxxxxxxxxxxxxxxxx",
        "pr_review_text_hunk": "LGTM with minor comments",
        "internal_jwt": "eyJhbGciOi...",
        "sql_query_text": "DROP TABLE analysis_runs;",
        "git_patch_chunk": "@@ -10,5 +10,6 @@",
    })

    # Test sanitize_span_attributes drops all 32 dynamic forbidden keys
    sanitized = sanitize_span_attributes(dynamic_forbidden)
    assert sanitized == {}, f"Expected empty dict, got {sanitized}"

    # Test SafeSpanWrapper drops all 32 keys
    wrapper.set_attributes(dynamic_forbidden)
    assert raw_span.set_attribute.call_count == 0

    # Test individual set_attribute with dynamic keys
    for k, v in dynamic_forbidden.items():
        wrapper.set_attribute(k, v)
    assert raw_span.set_attribute.call_count == 0

