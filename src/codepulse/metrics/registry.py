"""Prometheus metric registry and metric definitions (§9.2, DEC-016)."""

from __future__ import annotations

import os
import threading
from typing import Final

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
)

from codepulse.metrics.labels import (
    bound_endpoint,
    bound_installation,
    bound_repository,
)

# Standard latency buckets in seconds
LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    0.01,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
)

CHUNK_BUCKETS: Final[tuple[float, ...]] = (1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0)

# Ensure multiprocess dir exists if specified in environment
_multiproc_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
if _multiproc_dir:
    os.makedirs(_multiproc_dir, exist_ok=True)


# ==============================================================================
# The 13 Key Metrics from §9.2 (+ standard aliases)
# ==============================================================================

# 1. Webhook traffic volume and classification
WEBHOOKS_RECEIVED = Counter(
    "codepulse_webhooks_received_total",
    "Webhook traffic volume and classification",
    ["event_type", "action", "status"],
)
# Alias for §9.2 / test compatibility
WEBHOOK_EVENTS_TOTAL = Counter(
    "webhook_events_total",
    "Alias for webhook events total count",
    ["event_type", "action", "status"],
)

# 2. Analysis completion rate
ANALYSIS_RUNS_TOTAL = Counter(
    "codepulse_analysis_runs_total",
    "Analysis runs completion rate by status and repository",
    ["status", "repository"],
)

# 3. Per-phase latency distribution
ANALYSIS_DURATION_SECONDS = Histogram(
    "codepulse_analysis_duration_seconds",
    "Per-phase latency distribution",
    ["phase", "repository"],
    buckets=LATENCY_BUCKETS,
)

# 4. Webhook-to-posted-review latency (end-to-end)
END_TO_END_DURATION_SECONDS = Histogram(
    "codepulse_end_to_end_duration_seconds",
    "Webhook-to-posted-review latency",
    ["repository"],
    buckets=LATENCY_BUCKETS,
)
# Overall pipeline duration by status (for p99 recording rule & Grafana)
PIPELINE_DURATION_SECONDS = Histogram(
    "codepulse_pipeline_duration_seconds",
    "Pipeline execution duration in seconds by completion status",
    ["status"],
    buckets=LATENCY_BUCKETS,
)

# 5. Finding distribution
FINDINGS_TOTAL = Counter(
    "codepulse_findings_total",
    "Security and quality findings distribution",
    ["severity", "category", "source"],
)

# 6. LLM cache effectiveness
LLM_CACHE_HIT_RATIO = Gauge(
    "codepulse_llm_cache_hit_ratio",
    "LLM cache hit ratio (0.0 to 1.0)",
    multiprocess_mode="mostrecent",
)

# 7. LLM cost tracking & tokens
LLM_TOKENS_CONSUMED = Counter(
    "codepulse_llm_tokens_consumed_total",
    "LLM tokens consumed by model and direction (input/output)",
    ["model", "direction"],
)
LLM_TOKENS_TOTAL = Counter(
    "codepulse_llm_tokens_total",
    "Alias for LLM tokens by model and token_type",
    ["model", "token_type"],
)
LLM_COST_CENTS_TOTAL = Counter(
    "codepulse_llm_cost_cents_total",
    "Estimated cumulative LLM API costs in USD cents",
    ["model"],
)

# 8. Per-call LLM API latency
LLM_LATENCY_SECONDS = Histogram(
    "codepulse_llm_latency_seconds",
    "Per-call LLM API latency",
    ["model", "cache_hit"],
    buckets=LATENCY_BUCKETS,
)

# 9. GitHub API usage
GITHUB_API_CALLS_TOTAL = Counter(
    "codepulse_github_api_calls_total",
    "GitHub API calls total by endpoint and status code",
    ["endpoint", "status_code"],
)

# 10. Rate limit headroom
GITHUB_API_RATE_LIMIT_REMAINING = Gauge(
    "codepulse_github_api_rate_limit_remaining",
    "GitHub API rate limit remaining requests",
    ["installation_id"],
    multiprocess_mode="mostrecent",
)

# 11. Circuit breaker state (0=closed, 1=open, 0.5=half-open)
CIRCUIT_BREAKER_STATE = Gauge(
    "codepulse_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=open, 0.5=half-open)",
    ["api"],
    multiprocess_mode="mostrecent",
)

# 12. Dead-letter volume
DEAD_LETTER_TOTAL = Counter(
    "codepulse_dead_letter_total",
    "Durable dead letter volume by task name",
    ["task_name"],
)

# 13. Distribution of chunk counts per PR
CHUNKS_PER_ANALYSIS = Histogram(
    "codepulse_chunks_per_analysis",
    "Distribution of diff chunk counts per PR analysis",
    buckets=CHUNK_BUCKETS,
)

# Additional Resilience & Worker Metrics
RATE_LIMIT_WAIT_SECONDS = Counter(
    "codepulse_rate_limit_wait_seconds",
    "Total seconds tasks delayed due to rate limiting",
    ["api"],
)

CELERY_TASK_DURATION_SECONDS = Histogram(
    "celery_task_duration_seconds",
    "Celery task duration distribution by task name and status",
    ["task_name", "status"],
    buckets=LATENCY_BUCKETS,
)

CELERY_QUEUE_DEPTH = Gauge(
    "celery_queue_depth",
    "Celery queue depth by queue name",
    ["queue"],
    multiprocess_mode="mostrecent",
)

# Map of the 13 canonical metric names for reflection and tests
CANONICAL_METRICS: Final[dict[str, Any]] = {
    "codepulse_webhooks_received_total": WEBHOOKS_RECEIVED,
    "codepulse_analysis_runs_total": ANALYSIS_RUNS_TOTAL,
    "codepulse_analysis_duration_seconds": ANALYSIS_DURATION_SECONDS,
    "codepulse_end_to_end_duration_seconds": END_TO_END_DURATION_SECONDS,
    "codepulse_findings_total": FINDINGS_TOTAL,
    "codepulse_llm_cache_hit_ratio": LLM_CACHE_HIT_RATIO,
    "codepulse_llm_tokens_consumed_total": LLM_TOKENS_CONSUMED,
    "codepulse_llm_latency_seconds": LLM_LATENCY_SECONDS,
    "codepulse_github_api_calls_total": GITHUB_API_CALLS_TOTAL,
    "codepulse_github_api_rate_limit_remaining": GITHUB_API_RATE_LIMIT_REMAINING,
    "codepulse_circuit_breaker_state": CIRCUIT_BREAKER_STATE,
    "codepulse_dead_letter_total": DEAD_LETTER_TOTAL,
    "codepulse_chunks_per_analysis": CHUNKS_PER_ANALYSIS,
}


def record_webhook_received(event_type: str, action: str, status: str) -> None:
    """Record a webhook reception event."""
    WEBHOOKS_RECEIVED.labels(event_type=event_type, action=action, status=status).inc()
    WEBHOOK_EVENTS_TOTAL.labels(event_type=event_type, action=action, status=status).inc()


def record_analysis_run(status: str, repository: str) -> None:
    """Record an analysis run completion."""
    bounded_repo = bound_repository(repository)
    ANALYSIS_RUNS_TOTAL.labels(status=status, repository=bounded_repo).inc()


def record_pipeline_duration(duration_seconds: float, status: str = "completed", repository: str | None = None) -> None:
    """Record end-to-end pipeline duration."""
    if repository:
        bounded_repo = bound_repository(repository)
        END_TO_END_DURATION_SECONDS.labels(repository=bounded_repo).observe(duration_seconds)
    PIPELINE_DURATION_SECONDS.labels(status=status).observe(duration_seconds)


def record_finding(severity: str, category: str, source: str) -> None:
    """Record a detected finding."""
    FINDINGS_TOTAL.labels(
        severity=severity.lower(),
        category=category.upper(),
        source=source.lower(),
    ).inc()


def record_analysis_phase_duration(phase: str, duration_seconds: float, repository: str | None = None) -> None:
    """Record per-phase latency distribution (§9.2)."""
    bounded_repo = bound_repository(repository)
    ANALYSIS_DURATION_SECONDS.labels(phase=phase, repository=bounded_repo).observe(duration_seconds)


_cache_hits = 0
_cache_total = 0
_cache_lock = threading.Lock()


def record_llm_telemetry(
    model: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
    cache_hit: bool,
) -> None:
    """Record LLM inference telemetry."""
    global _cache_hits, _cache_total
    cache_str = "true" if cache_hit else "false"
    latency_sec = latency_ms / 1000.0 if latency_ms else 0.0

    LLM_LATENCY_SECONDS.labels(model=model, cache_hit=cache_str).observe(latency_sec)
    LLM_TOKENS_CONSUMED.labels(model=model, direction="input").inc(input_tokens)
    LLM_TOKENS_CONSUMED.labels(model=model, direction="output").inc(output_tokens)
    LLM_TOKENS_TOTAL.labels(model=model, token_type="input").inc(input_tokens)
    LLM_TOKENS_TOTAL.labels(model=model, token_type="output").inc(output_tokens)

    # Cost calculation: Gemini 3.7 Flash pricing ($0.075 / 1M input tokens, $0.30 / 1M output tokens)
    cost_cents = (input_tokens * 0.000075 + output_tokens * 0.00030) * 100
    LLM_COST_CENTS_TOTAL.labels(model=model).inc(cost_cents)

    with _cache_lock:
        _cache_total += 1
        if cache_hit:
            _cache_hits += 1
        ratio = _cache_hits / _cache_total if _cache_total > 0 else 0.0
        LLM_CACHE_HIT_RATIO.set(ratio)


def record_circuit_breaker(api: str, state_value: float) -> None:
    """Record circuit breaker state (0=closed, 1=open, 0.5=half-open)."""
    CIRCUIT_BREAKER_STATE.labels(api=api).set(state_value)


def record_dead_letter_metric(task_name: str) -> None:
    """Record dead letter queue placement."""
    DEAD_LETTER_TOTAL.labels(task_name=task_name).inc()


def record_github_api_call(endpoint: str, status_code: int) -> None:
    """Record a GitHub API call."""
    bounded_ep = bound_endpoint(endpoint)
    GITHUB_API_CALLS_TOTAL.labels(endpoint=bounded_ep, status_code=str(status_code)).inc()


def record_github_rate_limit(installation_id: Any, remaining: int) -> None:
    """Record GitHub API rate limit remaining."""
    bounded_inst = bound_installation(installation_id)
    GITHUB_API_RATE_LIMIT_REMAINING.labels(installation_id=bounded_inst).set(remaining)


def generate_prometheus_metrics() -> bytes:
    """Generate Prometheus exposition format bytes (supporting multiprocess mode)."""
    multiproc_dir = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if multiproc_dir and os.path.isdir(multiproc_dir):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry)
    return generate_latest(REGISTRY)
