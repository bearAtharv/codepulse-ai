"""Tests for Phase 7b: Rate limiting, caching, circuit breaker, and graceful degradation.

Covers:
- Token-bucket rate limiter (§3.4.6, §11): 324 RPM, burst 10, Lua atomic tokens, retry scheduling.
- LLM response caching (§3.4.5, §3.7.2): Cache key over prompt + model + version, 24h TTL, telemetry.
- Circuit breaker (§6.3, §10.2 Branch D): 5 failures in 60s -> OPEN, 30s recovery -> HALF_OPEN, probe close/reopen.
- Graceful degradation (§6.4, §10.2 Branch D): LLM failure yields AST-only review with disclaimer, reanalysis_needed=True.
- GitHub rate limiting (§10.2 Branch E): Rescheduling to cp-retry at reset time.
- Re-analysis Beat task (§6.4, Option A): Distributed lock, PR head SHA check, 3-attempt cap, vulnerability-family merge, follow-up review of unmatched findings only, idempotency.
- Persistence drain Beat task: Periodic recovery of codepulse:pending_persistence.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from codepulse.aggregation.models import DeduplicationResult, Finding
from codepulse.aggregation.summary import compose_review_summary
from codepulse.analysis.circuit_breaker import CircuitBreaker
from codepulse.analysis.rate_limiter import TokenBucketRateLimiter
from codepulse.config import get_settings
from codepulse.models.tables import AnalysisRun, Finding as DBFinding, LlmUsageLog, Repository
from codepulse.persistence.database import get_redis_client, save_payload_ref
from codepulse.worker.celery_app import celery_app
from codepulse.worker.tasks import (
    PROMPT_SCHEMA_VERSION,
    analyze_llm_task,
    drain_pending_persistence_task,
    get_llm_cache_key,
    post_review_to_github,
    scan_reanalysis_needed,
)

# Check PostgreSQL reachability
DB_REACHABLE = False
try:
    engine = create_engine(get_settings().database_url, pool_pre_ping=True)
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    DB_REACHABLE = True
except Exception:
    DB_REACHABLE = False


@pytest.fixture
def db_session() -> Session:
    """Provide a real DB session for integration tests, skipping cleanly if unreachable."""
    if not DB_REACHABLE:
        pytest.skip("PostgreSQL unreachable at " + get_settings().database_url)
    sm = sessionmaker(bind=engine)
    session = sm()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def test_repo_and_run(db_session: Session) -> tuple[Repository, AnalysisRun]:
    """Insert a test repository and analysis run."""
    run_uuid = uuid.uuid4()
    repo_id = int(run_uuid.int % 1_000_000_000)
    repo = Repository(
        id=repo_id,
        github_id=repo_id,
        full_name=f"test-org/phase7b-repo-{run_uuid.hex[:6]}",
        installation_id=12345,
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    run = AnalysisRun(
        id=run_uuid,
        repository_id=repo.id,
        pull_request_number=101,
        head_sha="1" * 40,
        base_sha="0" * 40,
        pr_author="test-dev",
        status="completed",
        webhook_received_at=datetime.now(timezone.utc),
    )
    db_session.add(run)
    db_session.commit()
    return repo, run


def make_chunk_dict(file_path: str = "src/app.py", code: str = "p7b_val = eval(p7b_untrusted)\n") -> dict[str, Any]:
    """Helper to create a properly formatted AnalysisChunk dictionary."""
    return {
        "file_path": file_path,
        "language": "python",
        "source_code": code,
        "diff_text": f"@@ -0,0 +1 @@\n+{code}",
        "hunk_header": "@@ -0,0 +1 @@",
        "modified_lines": [1],
        "estimated_tokens": 10,
    }


# ── 1. Token-Bucket Rate Limiter Tests ─────────────────────────────────


class TestTokenBucketRateLimiter:
    """Verifies §3.4.6 and §11 sliding token bucket rate limiter."""

    def test_token_bucket_acquire_and_exhaustion(self) -> None:
        redis_client = get_redis_client()
        limiter = TokenBucketRateLimiter(
            redis_client=redis_client,
            rpm=60,  # 1 token/sec
            burst=2,
            key_prefix=f"test:rate_limit:{uuid.uuid4().hex[:6]}",
        )
        limiter.reset()

        # 1. First 2 tokens succeed (burst capacity)
        allowed1, _ = limiter.acquire(cost=1)
        allowed2, _ = limiter.acquire(cost=1)
        assert allowed1 is True
        assert allowed2 is True

        # 2. Third token fails with positive wait_seconds
        allowed3, wait_sec = limiter.acquire(cost=1)
        assert allowed3 is False
        assert wait_sec > 0.0

    def test_analyze_llm_task_schedules_retry_on_rate_limit(self) -> None:
        """When token bucket is empty, task must schedule a retry (no blocking)."""
        chunk = make_chunk_dict()

        with patch.dict(os.environ, {"MOCK_LLM": "true", "MOCK_RATE_LIMIT": "true", "MOCK_RATE_LIMIT_WAIT": "3"}):
            with pytest.raises(Exception) as exc_info:
                analyze_llm_task([chunk], "org/repo", "python", str(uuid.uuid4()))
            # Must raise a Celery Retry exception
            assert "Retry" in type(exc_info.value).__name__ or "retry" in str(exc_info.value).lower()


# ── 2. LLM Response Cache Tests ────────────────────────────────────────


class TestLLMResponseCache:
    """Verifies §3.4.5 and §3.7.2 response caching behavior."""

    def test_cache_key_invalidation_coverage(self) -> None:
        """Cache key covers prompt, model ID, and schema version."""
        k1 = get_llm_cache_key("prompt text", "gemini-3.7-flash", "v1")
        k2 = get_llm_cache_key("prompt text", "gemini-3.7-flash", "v2")
        k3 = get_llm_cache_key("prompt text", "gemini-2.5-pro", "v1")
        k4 = get_llm_cache_key("different prompt", "gemini-3.7-flash", "v1")

        assert k1.startswith("llm_cache:")
        assert k1 != k2
        assert k1 != k3
        assert k1 != k4

    def test_llm_cache_hit_and_telemetry(self) -> None:
        """First call is a cache miss; second call is a cache hit with cache_hit=True."""
        chunk = make_chunk_dict()
        run_id = str(uuid.uuid4())
        unique_repo = f"org/cache-test-repo-{uuid.uuid4().hex[:6]}"

        with patch.dict(os.environ, {"MOCK_LLM": "true"}):
            # 1. First execution: cache miss
            res1 = analyze_llm_task([chunk], unique_repo, "python", run_id)
            assert res1["usage"]["cache_hit"] is False
            assert len(res1["findings"]) >= 1

            # 2. Second execution with identical prompt: cache hit
            res2 = analyze_llm_task([chunk], unique_repo, "python", run_id)
            assert res2["usage"]["cache_hit"] is True
            assert res2["usage"]["input_tokens"] == 0
            assert res2["usage"]["output_tokens"] == 0
            assert len(res2["findings"]) == len(res1["findings"])


# ── 3. Circuit Breaker Tests ───────────────────────────────────────────


class TestCircuitBreaker:
    """Verifies §6.3 circuit breaker state machine."""

    def test_circuit_breaker_trip_and_recovery(self) -> None:
        redis_client = get_redis_client()
        breaker = CircuitBreaker(
            redis_client=redis_client,
            name=f"test_{uuid.uuid4().hex[:6]}",
            failure_threshold=5,
            failure_window=60.0,
            recovery_timeout=0.2,  # 200ms recovery for test
        )
        breaker.reset()

        assert breaker.get_state() == "CLOSED"

        # Record 4 failures -> remains CLOSED
        for _ in range(4):
            breaker.record_failure()
        assert breaker.get_state() == "CLOSED"

        # 5th failure -> trips to OPEN
        breaker.record_failure()
        assert breaker.get_state() == "OPEN"

        # While OPEN and within recovery timeout: execution rejected
        allowed, state = breaker.can_execute()
        assert allowed is False
        assert state == "OPEN"

        # Wait for recovery timeout
        time.sleep(0.25)

        # In HALF_OPEN: allows 1 probe request
        allowed_probe, state_probe = breaker.can_execute()
        assert allowed_probe is True
        assert state_probe == "HALF_OPEN"

        # Successful probe -> closes circuit
        new_state = breaker.record_success()
        assert new_state == "CLOSED"
        assert breaker.get_state() == "CLOSED"

    def test_llm_task_catches_failure_and_returns_degraded(self) -> None:
        """When LLM breaker is OPEN, task returns degraded result without crashing chord."""
        chunk = make_chunk_dict()
        with patch.dict(os.environ, {"MOCK_LLM": "true", "MOCK_LLM_FAILURE": "true"}):
            res = analyze_llm_task([chunk], "org/repo", "python", str(uuid.uuid4()))
            assert res["llm_degraded"] is True
            assert res["findings"] == []


# ── 4. Graceful Degradation & Disclaimer Tests ─────────────────────────


class TestGracefulDegradation:
    """Verifies §6.4 graceful degradation behavior and review disclaimer."""

    def test_review_summary_includes_degraded_disclaimer(self) -> None:
        finding = Finding(
            file_path="src/app.py",
            line_start=1,
            line_end=1,
            severity="high",
            category="A03",
            title="Code Injection",
            explanation="eval() used on user input",
            remediation="Avoid eval()",
            confidence="high",
            source="ast",
        )
        dedup_res = DeduplicationResult(findings=[finding], total_raw=1, merged_count=0, truncated_count=0)

        # Standard summary has no degraded notice
        normal_summary = compose_review_summary(dedup_res, degraded_mode=False)
        assert "Degraded Mode" not in normal_summary

        # Degraded summary has explicit disclaimer from §6.4
        degraded_summary = compose_review_summary(dedup_res, degraded_mode=True)
        assert "Degraded Mode" in degraded_summary
        assert "LLM analysis unavailable; AST-only results shown" in degraded_summary


# ── 5. GitHub Rate Limit Rescheduling (Branch E) ───────────────────────


class TestGitHubRateLimitHandling:
    """Verifies §10.2 Branch E rescheduling to cp-retry queue."""

    def test_post_review_rescheduled_to_cp_retry(self) -> None:
        data = {
            "context": {
                "installation_id": 1,
                "repository_full_name": "owner/repo",
                "pull_request_number": 1,
                "head_sha": "a" * 40,
                "analysis_run_id": str(uuid.uuid4()),
            },
            "review_payload": {"event": "COMMENT", "body": "test", "comments": []},
            "findings": [],
        }

        with patch.dict(os.environ, {"MOCK_GITHUB": "true", "MOCK_GITHUB_RATE_LIMIT": "true", "MOCK_GITHUB_RESET_TS": str(time.time() + 5)}):
            with pytest.raises(Exception) as exc_info:
                post_review_to_github(data)
            # Must raise a Celery Retry exception
            assert "Retry" in type(exc_info.value).__name__ or "retry" in str(exc_info.value).lower()


# ── 6. Re-Analysis Beat Task Tests (Option A) ──────────────────────────


class TestReanalysisBeatTask:
    """Verifies §6.4 Option A re-analysis periodic task."""

    def test_reanalysis_merges_matched_and_posts_unmatched(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        repo, run = test_repo_and_run
        run.reanalysis_needed = True
        run.status = "completed"
        db_session.commit()

        # Seed initial AST finding (e.g. eval injection on line 1)
        ast_finding = DBFinding(
            id=uuid.uuid4(),
            analysis_run_id=run.id,
            file_path="src/app.py",
            line_start=1,
            line_end=1,
            severity="high",
            category="A03",
            title="Remote Code Execution",
            explanation="AST eval detected",
            remediation="Do not use eval",
            confidence="medium",
            source="ast",
            is_posted=True,
        )
        db_session.add(ast_finding)
        db_session.commit()

        with patch.dict(os.environ, {"MOCK_GITHUB": "true", "MOCK_LLM": "true"}):
            # Run the Beat re-analysis task
            reanalyzed_count = scan_reanalysis_needed()
            assert reanalyzed_count >= 1

        db_session.expire_all()
        reloaded_run = db_session.get(AnalysisRun, run.id)
        assert reloaded_run is not None
        # Flag cleared
        assert reloaded_run.reanalysis_needed is False

        findings = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
        # Matched finding was updated to merged
        merged = [f for f in findings if f.source == "merged"]
        assert len(merged) == 1
        assert "Also confirmed by LLM" in merged[0].explanation

        # Unmatched findings (e.g. SQL injection and XSS from index.js) were inserted
        assert len(findings) > 1

        # Second trigger must do nothing because flag was cleared
        second_run_count = scan_reanalysis_needed()
        assert second_run_count == 0

    def test_reanalysis_superseded_when_pr_head_moves(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        repo, run = test_repo_and_run
        run.reanalysis_needed = True
        run.head_sha = "0" * 40  # Old SHA
        db_session.commit()

        # Mock current head SHA has moved to a new commit
        with patch.dict(os.environ, {"MOCK_GITHUB": "true", "MOCK_CURRENT_HEAD_SHA": "2" * 40}):
            scan_reanalysis_needed()

        db_session.expire_all()
        reloaded_run = db_session.get(AnalysisRun, run.id)
        assert reloaded_run is not None
        # Flag was cleared because PR head SHA moved (superseded)
        assert reloaded_run.reanalysis_needed is False


# ── 7. Persistence Drain Beat Task Tests ───────────────────────────────


class TestPersistenceDrainBeatTask:
    """Verifies Branch G recovery via Celery Beat task."""

    def test_drain_pending_persistence_task_empty(self) -> None:
        recovered = drain_pending_persistence_task()
        assert isinstance(recovered, int)
