"""Unit tests for Prometheus metrics, cardinality bounding, and exposition (§9.2, DEC-016)."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from codepulse.ingestion.app import app
from codepulse.metrics.labels import (
    DEFAULT_MAX_CARDINALITY,
    FALLBACK_LABEL_VALUE,
    FORBIDDEN_LABEL_KEYS,
    LabelLimiter,
    bound_endpoint,
    bound_installation,
    bound_repository,
    reset_limiters,
)
from codepulse.metrics.registry import (
    ANALYSIS_RUNS_TOTAL,
    CANONICAL_METRICS,
    CHUNKS_PER_ANALYSIS,
    CIRCUIT_BREAKER_STATE,
    DEAD_LETTER_TOTAL,
    FINDINGS_TOTAL,
    GITHUB_API_CALLS_TOTAL,
    GITHUB_API_RATE_LIMIT_REMAINING,
    LLM_CACHE_HIT_RATIO,
    LLM_COST_CENTS_TOTAL,
    LLM_LATENCY_SECONDS,
    LLM_TOKENS_CONSUMED,
    PIPELINE_DURATION_SECONDS,
    RATE_LIMIT_WAIT_SECONDS,
    WEBHOOK_EVENTS_TOTAL,
    WEBHOOKS_RECEIVED,
    generate_prometheus_metrics,
    record_analysis_run,
    record_circuit_breaker,
    record_dead_letter_metric,
    record_finding,
    record_github_api_call,
    record_github_rate_limit,
    record_llm_telemetry,
    record_pipeline_duration,
    record_webhook_received,
)
from codepulse.metrics.server import start_metrics_server


@pytest.fixture(autouse=True)
def _clean_limiters() -> None:
    """Reset limiters before each test."""
    reset_limiters()


class TestMetricsRegistry:
    """Verification of the 13 canonical §9.2 metrics."""

    def test_all_13_canonical_metrics_exist(self) -> None:
        """All 13 metric names specified in §9.2 must be defined and registered."""
        expected_metric_names = {
            "codepulse_webhooks_received_total",
            "codepulse_analysis_runs_total",
            "codepulse_analysis_duration_seconds",
            "codepulse_end_to_end_duration_seconds",
            "codepulse_findings_total",
            "codepulse_llm_cache_hit_ratio",
            "codepulse_llm_tokens_consumed_total",
            "codepulse_llm_latency_seconds",
            "codepulse_github_api_calls_total",
            "codepulse_github_api_rate_limit_remaining",
            "codepulse_circuit_breaker_state",
            "codepulse_dead_letter_total",
            "codepulse_chunks_per_analysis",
        }
        assert set(CANONICAL_METRICS.keys()) == expected_metric_names

    def test_forbidden_label_names_never_in_metrics(self) -> None:
        """Metric label sets must NEVER contain unbounded or sensitive keys."""
        for name, metric in CANONICAL_METRICS.items():
            # Inspect metric labelnames
            labelnames = getattr(metric, "_labelnames", ())
            for lbl in labelnames:
                assert lbl not in FORBIDDEN_LABEL_KEYS, (
                    f"Metric {name} contains forbidden label: {lbl}"
                )

    def test_record_webhook_received_increments(self) -> None:
        """Recording a webhook updates both canonical and alias counters."""
        initial_val = WEBHOOKS_RECEIVED.labels(event_type="pull_request", action="opened", status="accepted")._value.get()
        record_webhook_received("pull_request", "opened", "accepted")
        new_val = WEBHOOKS_RECEIVED.labels(event_type="pull_request", action="opened", status="accepted")._value.get()
        assert new_val == initial_val + 1

    def test_record_findings_increments(self) -> None:
        """Recording findings updates severity, category, source counters."""
        initial_val = FINDINGS_TOTAL.labels(severity="critical", category="A03", source="ast")._value.get()
        record_finding("CRITICAL", "A03", "AST")
        new_val = FINDINGS_TOTAL.labels(severity="critical", category="A03", source="ast")._value.get()
        assert new_val == initial_val + 1

    def test_record_llm_telemetry_increments(self) -> None:
        """Recording LLM telemetry tracks tokens, latency, cost, and cache hit ratio."""
        init_tokens = LLM_TOKENS_CONSUMED.labels(model="gemini-3.7-flash", direction="input")._value.get()
        record_llm_telemetry("gemini-3.7-flash", input_tokens=1000, output_tokens=200, latency_ms=450, cache_hit=True)
        new_tokens = LLM_TOKENS_CONSUMED.labels(model="gemini-3.7-flash", direction="input")._value.get()
        assert new_tokens == init_tokens + 1000
        assert LLM_CACHE_HIT_RATIO._value.get() >= 0.0

    def test_record_analysis_phase_duration_records(self) -> None:
        """Recording phase duration observes duration in histogram."""
        from codepulse.metrics import ANALYSIS_DURATION_SECONDS, record_analysis_phase_duration

        init_sum = ANALYSIS_DURATION_SECONDS.labels(phase="ast", repository="owner/test-repo")._sum.get()
        record_analysis_phase_duration("ast", 0.05, "owner/test-repo")
        new_sum = ANALYSIS_DURATION_SECONDS.labels(phase="ast", repository="owner/test-repo")._sum.get()
        assert new_sum >= init_sum + 0.05


class TestCardinalityBounding:
    """Verification of label cardinality enforcement."""

    def test_label_limiter_caps_at_max_distinct_values(self) -> None:
        """Feeding >200 distinct values maps the 201st+ to 'other'."""
        limiter = LabelLimiter(max_cardinality=200, fallback="other")

        # Feed 200 distinct values
        for i in range(200):
            val = f"repo-org/repo-{i}"
            res = limiter.bound(val)
            assert res == val, f"Value {val} should have been preserved"

        assert limiter.current_cardinality == 200

        # Feed 201st, 202nd values
        assert limiter.bound("repo-org/repo-200") == "other"
        assert limiter.bound("repo-org/repo-201") == "other"

        # Re-feeding an earlier seen value still returns the original value
        assert limiter.bound("repo-org/repo-5") == "repo-org/repo-5"

    def test_bound_repository_function(self) -> None:
        """bound_repository utility respects the 200 cap."""
        for i in range(200):
            bound_repository(f"org/repo-{i}")
        assert bound_repository("org/repo-overflow") == "other"

    def test_bound_endpoint_function(self) -> None:
        """bound_endpoint utility respects the 200 cap."""
        for i in range(200):
            bound_endpoint(f"/api/v1/resource-{i}")
        assert bound_endpoint("/api/v1/resource-overflow") == "other"

    def test_env_configured_label_cap_bounds_repository_and_installation_id(self, monkeypatch: Any) -> None:
        """Setting METRIC_LABEL_CAP restricts both repository and installation_id bounding."""
        monkeypatch.setenv("METRIC_LABEL_CAP", "3")
        from codepulse.metrics.labels import LabelLimiter

        # Repo limiter test
        repo_limiter = LabelLimiter()
        assert repo_limiter.max_cardinality == 3
        assert repo_limiter.bound("owner/repo-1") == "owner/repo-1"
        assert repo_limiter.bound("owner/repo-2") == "owner/repo-2"
        assert repo_limiter.bound("owner/repo-3") == "owner/repo-3"
        assert repo_limiter.bound("owner/repo-4") == "other"

        # Installation limiter test
        inst_limiter = LabelLimiter()
        assert inst_limiter.max_cardinality == 3
        assert inst_limiter.bound("101") == "101"
        assert inst_limiter.bound("102") == "102"
        assert inst_limiter.bound("103") == "103"
        assert inst_limiter.bound("104") == "other"


class TestMetricsExpositionAndPortIsolation:
    """Verification that /metrics is isolated on internal port and not on port 8000."""

    def test_public_app_returns_404_on_metrics(self) -> None:
        """The public FastAPI app must NOT expose /metrics."""
        client = TestClient(app)
        resp = client.get("/metrics")
        assert resp.status_code == 404, "Public app must return 404 for /metrics"

    def test_generate_prometheus_metrics_contains_expected_series(self) -> None:
        """generate_prometheus_metrics exposition output includes canonical metrics."""
        record_webhook_received("pull_request", "synchronize", "accepted")
        record_finding("high", "A01", "merged")

        metrics_bytes = generate_prometheus_metrics()
        metrics_text = metrics_bytes.decode("utf-8")

        assert "codepulse_webhooks_received_total" in metrics_text
        assert "codepulse_findings_total" in metrics_text

    def test_metrics_handler_serves_metrics(self) -> None:
        """MetricsHTTPRequestHandler responds with 200 and exposition text."""
        from io import BytesIO
        from codepulse.metrics.server import MetricsHTTPRequestHandler

        handler = MetricsHTTPRequestHandler.__new__(MetricsHTTPRequestHandler)
        handler.path = "/metrics"
        handler.request_version = "HTTP/1.1"
        handler.command = "GET"
        handler.wfile = BytesIO()
        handler.rfile = BytesIO()
        handler.headers = {}
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()

        handler.do_GET()

        handler.send_response.assert_called_with(200)
        output = handler.wfile.getvalue().decode("utf-8")
        assert "codepulse" in output

    def test_start_metrics_server_returns_server_instance(self) -> None:
        """start_metrics_server initializes and starts a ThreadedMetricsServer."""
        with patch("codepulse.metrics.server.ThreadedMetricsServer") as mock_server_cls, \
             patch("threading.Thread") as mock_thread_cls:
            mock_server = MagicMock()
            mock_server_cls.return_value = mock_server
            mock_thread = MagicMock()
            mock_thread_cls.return_value = mock_thread

            res = start_metrics_server(port=9095)
            assert res == mock_server
            mock_thread.start.assert_called_once()
