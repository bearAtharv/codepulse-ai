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
from datetime import datetime, timedelta, timezone
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

    def test_rate_limit_does_not_consume_failure_budget_or_trip_breaker(self) -> None:
        """Rate limit retry must NOT increment failure_retries and must NOT count as a circuit breaker failure."""
        chunk = make_chunk_dict()
        redis_client = get_redis_client()
        breaker = CircuitBreaker(redis_client, name="gemini")
        breaker.reset()

        with patch.dict(os.environ, {"MOCK_LLM": "true", "MOCK_RATE_LIMIT": "true", "MOCK_RATE_LIMIT_WAIT": "2"}):
            with pytest.raises(Exception):
                analyze_llm_task([chunk], "org/repo", "python", str(uuid.uuid4()), failure_retries=0)

        # 1. Breaker state must still be CLOSED with 0 recorded failures
        assert breaker.get_state() == "CLOSED"
        assert redis_client.get(breaker.failures_key) is None

    def test_rate_limit_retry_preserves_full_failure_budget(self) -> None:
        """A run that experiences rate limiting still retains its full 3-attempt failure retry budget."""
        chunk = make_chunk_dict()
        run_id = str(uuid.uuid4())

        # When an actual failure occurs, failure_retries=0 retries (attempt 1/3) with backoff, NOT degraded
        with patch.object(analyze_llm_task, "retry", side_effect=RuntimeError("ScheduledRetry")) as mock_retry:
            with patch.object(analyze_llm_task.request, "called_directly", False, create=True):
                with patch.dict(os.environ, {"MOCK_LLM": "true"}), patch(
                    "codepulse.worker.tasks.analyze_llm", side_effect=RuntimeError("API error")
                ):
                    with pytest.raises(RuntimeError) as exc_info:
                        analyze_llm_task([chunk], "org/repo", "python", run_id, failure_retries=0)
                    assert "ScheduledRetry" in str(exc_info.value)
                    mock_retry.assert_called_once()
                    call_kwargs = mock_retry.call_args[1]
                    # Failure count must increment to 1, preserving remaining budget
                    assert call_kwargs["kwargs"]["failure_retries"] == 1


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

    def test_reanalysis_skips_when_run_is_locked(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """When another worker holds the Redis lock for a run, re-analysis must skip it."""
        repo, run = test_repo_and_run
        run.reanalysis_needed = True
        db_session.commit()

        redis_client = get_redis_client()
        lock_key = f"lock:reanalyze:{run.id}"
        redis_client.set(lock_key, "1", ex=60)

        try:
            count = scan_reanalysis_needed()
            # Skipped because locked
            assert count == 0
            db_session.expire_all()
            reloaded_run = db_session.get(AnalysisRun, run.id)
            assert reloaded_run is not None
            assert reloaded_run.reanalysis_needed is True
        finally:
            redis_client.delete(lock_key)

    def test_reanalysis_attempt_cap_clears_flag(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """When attempt count exceeds 3, reanalysis_needed must be cleared with an error message."""
        repo, run = test_repo_and_run
        run.reanalysis_needed = True
        db_session.commit()

        redis_client = get_redis_client()
        attempt_key = f"reanalyze:attempts:{run.id}"
        redis_client.set(attempt_key, "3")

        try:
            scan_reanalysis_needed()
            db_session.expire_all()
            reloaded_run = db_session.get(AnalysisRun, run.id)
            assert reloaded_run is not None
            # Flag cleared and error message recorded
            assert reloaded_run.reanalysis_needed is False
            assert "attempts exhausted (cap: 3)" in (reloaded_run.error_message or "")
        finally:
            redis_client.delete(attempt_key)


# ── 7. Persistence Drain Beat Task Tests ───────────────────────────────


class TestPersistenceDrainBeatTask:
    """Verifies Branch G recovery via Celery Beat task."""

    def test_drain_pending_persistence_task_empty(self) -> None:
        recovered = drain_pending_persistence_task()
        assert isinstance(recovered, int)

    def test_drain_pending_persistence_commits_to_database_and_normalizes_confidence(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """Verifies drain_pending_persistence_task commits to DB and handles non-string confidence."""
        repo, run = test_repo_and_run
        run.status = "running"
        db_session.commit()

        redis_client = get_redis_client()
        payload = {
            "analysis_run_id": str(run.id),
            "status": "completed",
            "files_analyzed": 1,
            "chunks_total": 1,
            "chunks_completed": 1,
            "analysis_duration_ms": 100,
            "github_review_id": 987654321,
            "review_posted_at": "2026-10-27T08:00:00+00:00",
            "findings": [
                {
                    "file_path": "src/app.py",
                    "line_start": 10,
                    "line_end": 10,
                    "severity": "critical",
                    "category": "A01",
                    "title": "Recovered Vulnerability",
                    "explanation": "Persisted from pending queue",
                    "remediation": "Sanitize inputs",
                    "confidence": 0.99,  # Float: must be normalized to string
                    "source": "ast",
                    "rule_id": "test-rule",
                    "raw_category": "A01",
                    "suggested_fix": None,
                    "diff_line": 10,
                    "diff_start_line": None,
                    "diff_side": "RIGHT",
                    "is_in_diff": True,
                }
            ],
            "llm_usages": [],
        }

        import json
        redis_client.set(f"dead_letter:persist:{run.id}", json.dumps(payload), ex=3600)
        redis_client.rpush("codepulse:pending_persistence", str(run.id))

        try:
            recovered = drain_pending_persistence_task()
            assert recovered >= 1

            db_session.expire_all()
            reloaded_run = db_session.get(AnalysisRun, run.id)
            assert reloaded_run is not None
            assert reloaded_run.status == "completed"
            assert reloaded_run.github_review_id == 987654321

            findings = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
            assert len(findings) == 1
            assert findings[0].title == "Recovered Vulnerability"
            assert isinstance(findings[0].confidence, str)
            assert findings[0].confidence == "high"
        finally:
            redis_client.delete(f"dead_letter:persist:{run.id}")


# ── 8. Rate Limit Jitter, Deadline & Degradation Tests ───────────────────


class TestRateLimitHardening:
    """Verifies jitter, wait deadlines, RPM=0 safety, and degraded methodology disclosures."""

    def test_normalize_confidence_logs_warning_on_unexpected_value(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """normalize_confidence must log a warning on unexpected/coerced values."""
        import logging
        from codepulse.worker.tasks import normalize_confidence

        with caplog.at_level(logging.WARNING):
            c1 = normalize_confidence(0.95)
            assert c1 == "high"
            assert "Coerced numeric confidence 0.95 to canonical 'high'" in caplog.text

            caplog.clear()
            c2 = normalize_confidence("bogus_confidence")
            assert c2 == "medium"
            assert "Coerced unknown string confidence 'bogus_confidence' to 'medium'" in caplog.text

            caplog.clear()
            c3 = normalize_confidence(None)
            assert c3 == "medium"
            assert "Coerced unexpected confidence value None" in caplog.text

    def test_degraded_review_methodology_discloses_llm_skipped(self) -> None:
        """When degraded_mode=True, methodology block must disclose LLM skipped, not dual-analysis."""
        from codepulse.aggregation.models import DeduplicationResult
        from codepulse.aggregation.summary import compose_review_summary

        dedup_res = DeduplicationResult(findings=[], total_raw=0, merged_count=0, truncated_count=0)
        # 1. Normal mode: claims dual-analysis pipeline
        normal_body = compose_review_summary(
            dedup_result=dedup_res,
            files_analyzed=1,
            analysis_duration_ms=50,
            model_version="gemini-3.7-flash",
            degraded_mode=False,
        )
        assert "using a dual-analysis pipeline" in normal_body
        assert "Multi-chunk reasoning via Google `gemini-3.7-flash`" in normal_body

        # 2. Degraded mode: must NOT claim dual-analysis and must state LLM was skipped
        degraded_body = compose_review_summary(
            dedup_result=dedup_res,
            files_analyzed=1,
            analysis_duration_ms=50,
            model_version="gemini-3.7-flash",
            degraded_mode=True,
        )
        assert "using a dual-analysis pipeline" not in degraded_body
        assert "Multi-chunk reasoning via Google `gemini-3.7-flash`" not in degraded_body
        assert "in degraded AST-only mode:" in degraded_body
        assert "Skipped (service unavailable; re-analysis scheduled per §6.4)" in degraded_body

    def test_rate_limit_retry_includes_jitter(self) -> None:
        """Rate limit retry countdown must include random jitter."""
        chunk = make_chunk_dict()
        run_id = str(uuid.uuid4())
        unique_repo = f"org/repo-jitter-{uuid.uuid4()}"

        with patch.object(analyze_llm_task, "retry", side_effect=RuntimeError("ScheduledRetry")) as mock_retry:
            with patch.object(analyze_llm_task.request, "called_directly", False, create=True):
                with patch.dict(os.environ, {"MOCK_LLM": "true", "MOCK_RATE_LIMIT": "true", "MOCK_RATE_LIMIT_WAIT": "5.0"}):
                    with pytest.raises(RuntimeError):
                        analyze_llm_task([chunk], unique_repo, "python", run_id)
                    mock_retry.assert_called_once()
                    countdown = mock_retry.call_args[1]["countdown"]
                    # wait_seconds is 5.0, jitter is [0.1, 1.5] -> countdown in (5.0, 7.0]
                    assert countdown > 5.0
                    assert countdown <= 7.0

    def test_rate_limit_deadline_exceeded_degrades_to_ast_only(self) -> None:
        """When rate limit wait exceeds overall deadline, task must degrade to AST-only without retrying."""
        chunk = make_chunk_dict()
        run_id = str(uuid.uuid4())
        unique_repo = f"org/repo-deadline-{uuid.uuid4()}"

        # Deadline already passed (now - 10s)
        expired_deadline = time.time() - 10.0

        with patch.dict(os.environ, {"MOCK_LLM": "true", "MOCK_RATE_LIMIT": "true", "MOCK_RATE_LIMIT_WAIT": "5.0"}):
            res = analyze_llm_task(
                [chunk], unique_repo, "python", run_id, rate_limit_deadline=expired_deadline
            )
            assert res["degraded"] is True
            assert res["error"] == "Rate limit wait deadline exceeded"
            assert res["findings"] == []

    def test_rate_limit_rpm_zero_degrades_immediately_without_infinite_loop(self) -> None:
        """When RPM is misconfigured to 0, task must degrade immediately rather than looping forever."""
        chunk = make_chunk_dict()
        run_id = str(uuid.uuid4())
        unique_repo = f"org/repo-rpm0-{uuid.uuid4()}"

        with patch.dict(os.environ, {"MOCK_LLM": "true", "GEMINI_RPM_LIMIT": "0"}):
            res = analyze_llm_task([chunk], unique_repo, "python", run_id)
            assert res["degraded"] is True
            assert res["error"] == "Rate limit wait deadline exceeded"
            assert res["findings"] == []

    def test_scan_reanalysis_needed_followup_failure_records_dead_letter_and_preserves_reanalysis_needed(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """If follow-up review posting fails, dead letter is logged via Branch F path and reanalysis_needed stays True."""
        db_session.query(AnalysisRun).filter(AnalysisRun.reanalysis_needed == True).update({"reanalysis_needed": False})  # noqa: E712
        repo, run = test_repo_and_run
        run.reanalysis_needed = True
        run.head_sha = "1" * 40
        run.github_review_id = 55554444
        db_session.commit()

        redis_client = get_redis_client()
        # Mock Diff
        from codepulse.persistence.database import save_payload_ref
        save_payload_ref(
            f"diff:{run.id}",
            "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,2 +1,2 @@\n-line\n+import os; os.system(cmd)\n",
            ttl=300,
        )

        with patch("codepulse.worker.tasks.get_github_poster") as mock_poster_factory:
            mock_poster = MagicMock()
            mock_poster.post_review.side_effect = RuntimeError("GitHub 502 Bad Gateway")
            mock_poster_factory.return_value = mock_poster

            with patch("codepulse.worker.tasks.analyze_llm") as mock_analyze_llm:
                from codepulse.analysis.llm_engine import LLMAnalysisResult
                from codepulse.analysis.llm_schemas import (
                    Confidence,
                    LLMFindingItem,
                    LLMResponseMetadata,
                    LLMTokenUsage,
                    Severity,
                )
                mock_analyze_llm.return_value = LLMAnalysisResult(
                    findings=[
                        LLMFindingItem(
                            file_path="src/app.py",
                            line_start=1,
                            line_end=1,
                            category="A03",
                            title="Command Injection",
                            explanation="os.system with untrusted input",
                            remediation="Use subprocess",
                            confidence=Confidence.high,
                            severity=Severity.critical,
                        )
                    ],
                    metadata=LLMResponseMetadata(
                        model_version="gemini-3.7-flash",
                        prompt_version="1.0",
                        token_usage=LLMTokenUsage(input=10, output=10, total=20),
                    ),
                )

                scan_reanalysis_needed()

                db_session.expire_all()
                reloaded_run = db_session.get(AnalysisRun, run.id)
                assert reloaded_run is not None
                # Flag must NOT be cleared because review post failed
                assert reloaded_run.reanalysis_needed is True
                # Finding must NOT be lost: stored in DB with is_posted=False
                findings = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
                assert len(findings) == 1
                assert findings[0].title == "Command Injection"
                assert findings[0].is_posted is False

                # Branch F dead-letter entry recorded
                from codepulse.models.tables import DeadLetterLog
                dead_letter = (
                    db_session.query(DeadLetterLog)
                    .filter(DeadLetterLog.task_name == "tasks.post_review_to_github")
                    .order_by(DeadLetterLog.id.desc())
                    .first()
                )
                assert dead_letter is not None
                assert dead_letter.task_args.get("analysis_run_id") == str(run.id)
                assert dead_letter.resolved is False

    def test_scan_reanalysis_needed_stores_followup_review_id_in_redis(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """When follow-up review succeeds, review ID is stored in Redis without schema change."""
        db_session.query(AnalysisRun).filter(AnalysisRun.reanalysis_needed == True).update({"reanalysis_needed": False})  # noqa: E712
        repo, run = test_repo_and_run
        run.reanalysis_needed = True
        run.head_sha = "1" * 40
        run.github_review_id = 55554444
        db_session.commit()

        redis_client = get_redis_client()
        from codepulse.persistence.database import save_payload_ref
        save_payload_ref(
            f"diff:{run.id}",
            "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,2 +1,2 @@\n-line\n+import os; os.system(cmd)\n",
            ttl=300,
        )

        with patch("codepulse.worker.tasks.get_github_poster") as mock_poster_factory:
            mock_poster = MagicMock()
            mock_poster.post_review.return_value = {"id": 99887766}
            mock_poster_factory.return_value = mock_poster

            with patch("codepulse.worker.tasks.analyze_llm") as mock_analyze_llm:
                from codepulse.analysis.llm_engine import LLMAnalysisResult
                from codepulse.analysis.llm_schemas import (
                    Confidence,
                    LLMFindingItem,
                    LLMResponseMetadata,
                    LLMTokenUsage,
                    Severity,
                )
                mock_analyze_llm.return_value = LLMAnalysisResult(
                    findings=[
                        LLMFindingItem(
                            file_path="src/app.py",
                            line_start=1,
                            line_end=1,
                            category="A03",
                            title="Command Injection",
                            explanation="os.system with untrusted input",
                            remediation="Use subprocess",
                            confidence=Confidence.high,
                            severity=Severity.critical,
                        )
                    ],
                    metadata=LLMResponseMetadata(
                        model_version="gemini-3.7-flash",
                        prompt_version="1.0",
                        token_usage=LLMTokenUsage(input=10, output=10, total=20),
                    ),
                )

                scan_reanalysis_needed()

                db_session.expire_all()
                reloaded_run = db_session.get(AnalysisRun, run.id)
                assert reloaded_run is not None
                assert reloaded_run.reanalysis_needed is False
                assert reloaded_run.github_review_id == 55554444

                # Verify follow-up review ID stored in Redis
                stored_id = redis_client.get(f"reanalysis:review_id:{run.id}")
                assert stored_id is not None
                stored_id_str = stored_id if isinstance(stored_id, str) else stored_id.decode()
                assert stored_id_str == "99887766"

    def test_scan_reanalysis_needed_subsequent_scan_posts_previously_failed_unposted_findings(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """A subsequent scan must post previously unposted findings (is_posted=False) instead of dropping them."""
        db_session.query(AnalysisRun).filter(AnalysisRun.reanalysis_needed == True).update({"reanalysis_needed": False})  # noqa: E712
        repo, run = test_repo_and_run
        run.reanalysis_needed = True
        run.status = "completed"
        run.github_review_id = 11112222
        db_session.commit()

        # Existing unposted finding from a prior failed follow-up attempt
        unposted_finding = DBFinding(
            id=uuid.uuid4(),
            analysis_run_id=run.id,
            file_path="src/app.py",
            line_start=10,
            line_end=10,
            severity="critical",
            category="A03",
            title="Unposted Vulnerability",
            explanation="Unposted injection flaw",
            remediation="Fix it",
            confidence="high",
            source="llm",
            is_posted=False,
        )
        db_session.add(unposted_finding)
        db_session.commit()

        save_payload_ref(
            f"diff:{run.id}",
            "--- a/src/app.py\n+++ b/src/app.py\n@@ -10,2 +10,2 @@\n-line\n+eval(user_input)\n",
            ttl=300,
        )

        with patch("codepulse.worker.tasks.get_github_poster") as mock_poster_factory:
            mock_poster = MagicMock()
            mock_poster.post_review.return_value = {"id": 99887766}
            mock_poster_factory.return_value = mock_poster

            with patch("codepulse.worker.tasks.analyze_llm") as mock_analyze_llm:
                from codepulse.analysis.llm_engine import LLMAnalysisResult
                from codepulse.analysis.llm_schemas import (
                    Confidence,
                    LLMFindingItem,
                    LLMResponseMetadata,
                    LLMTokenUsage,
                    Severity,
                )
                # LLM returns identical finding
                mock_analyze_llm.return_value = LLMAnalysisResult(
                    findings=[
                        LLMFindingItem(
                            file_path="src/app.py",
                            line_start=10,
                            line_end=10,
                            category="A03",
                            title="Unposted Vulnerability",
                            explanation="Unposted injection flaw",
                            remediation="Fix it",
                            confidence=Confidence.high,
                            severity=Severity.critical,
                        )
                    ],
                    metadata=LLMResponseMetadata(
                        model_version="gemini-3.7-flash",
                        prompt_version="1.0",
                        token_usage=LLMTokenUsage(input=10, output=10, total=20),
                    ),
                )

                scan_reanalysis_needed()

                db_session.expire_all()
                reloaded_finding = db_session.get(DBFinding, unposted_finding.id)
                assert reloaded_finding is not None
                # Must now be marked as posted!
                assert reloaded_finding.is_posted is True

                reloaded_run = db_session.get(AnalysisRun, run.id)
                assert reloaded_run is not None
                assert reloaded_run.reanalysis_needed is False
                # Primary review ID must remain untouched!
                assert reloaded_run.github_review_id == 11112222

                mock_poster.post_review.assert_called_once()
                call_payload = mock_poster.post_review.call_args[0][3]
                assert len(call_payload["comments"]) == 1
                assert call_payload["comments"][0]["path"] == "src/app.py"


class TestComposeAndTaskIsolationFixes:
    """Verifies compose defaults, non-GitHub rate limit exclusion, and admin retry follow-up protection."""

    def test_compose_failure_injection_variables_default_to_false(self) -> None:
        """All failure-injection variables in docker-compose.yml must default to false."""
        import re
        from pathlib import Path

        compose_text = Path("docker-compose.yml").read_text(encoding="utf-8")
        # Find all ${VAR:-default} patterns for MOCK_
        mock_matches = re.findall(r"\$\{(MOCK_[A-Z_]+):-([^}]+)\}", compose_text)
        assert len(mock_matches) > 0, "No mock variables found in docker-compose.yml"

        failure_flags = {
            "MOCK_POSTING_FAILURE",
            "MOCK_QUICK_RETRIES",
            "MOCK_GITHUB_RATE_LIMIT",
            "MOCK_LLM_FAILURE",
            "MOCK_RATE_LIMIT",
        }

        for var_name, default_val in mock_matches:
            if var_name in failure_flags:
                assert default_val.lower() == "false", (
                    f"Variable {var_name} must default to 'false' in docker-compose.yml, got '{default_val}'"
                )

    def test_non_github_tasks_never_wait_on_github_rate_limit(self) -> None:
        """Tasks that do not call GitHub (aggregate_findings, persist_results) must not check GitHub rate limits."""
        from codepulse.worker.tasks import persist_results

        data = {
            "context": {
                "repository_full_name": "org/repo",
                "pull_request_number": 1,
                "analysis_run_id": str(uuid.uuid4()),
            },
            "findings": [],
        }

        with patch.dict(os.environ, {"MOCK_GITHUB": "true", "MOCK_GITHUB_RATE_LIMIT": "true"}):
            with patch("codepulse.worker.tasks.persist_analysis_results", return_value=0):
                # persist_results must NOT raise a Celery retry
                res = persist_results(data)
                assert res.get("status") == "completed"

    def test_admin_retry_followup_review_preserves_primary_review_id(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """Admin retry of a follow-up review dead letter must NOT overwrite primary github_review_id."""
        from codepulse.ingestion.admin import retry_posting
        from codepulse.models.tables import DeadLetterLog

        repo, run = test_repo_and_run
        primary_review_id = 12345678
        run.github_review_id = primary_review_id
        run.reanalysis_needed = True
        db_session.commit()

        # Seed unposted finding
        unposted = DBFinding(
            id=uuid.uuid4(),
            analysis_run_id=run.id,
            file_path="src/app.py",
            line_start=1,
            line_end=1,
            severity="high",
            category="A03",
            title="Late Finding",
            explanation="Explanation",
            remediation="Remediation",
            confidence="high",
            source="llm",
            is_posted=False,
        )
        db_session.add(unposted)

        # Seed follow-up review dead letter
        dl = DeadLetterLog(
            task_name="tasks.post_review_to_github",
            task_id=uuid.uuid4(),
            task_args={
                "analysis_run_id": str(run.id),
                "review_payload": {
                    "event": "COMMENT",
                    "body": "### 🛡️ CodePulse AI — Follow-up LLM analysis\n\nNew findings",
                    "comments": [],
                },
            },
            exception_type="RuntimeError",
            exception_message="Failed",
            traceback="Traceback",
            retry_count=5,
            resolved=False,
        )
        db_session.add(dl)
        db_session.commit()

        with patch("codepulse.ingestion.admin.get_github_poster") as mock_poster_factory:
            mock_poster = MagicMock()
            mock_poster.post_review.return_value = {"id": 99998888}
            mock_poster_factory.return_value = mock_poster

            resp = retry_posting(str(run.id), db=db_session, _=None)
            assert resp.status_code == 200

            db_session.expire_all()
            reloaded_run = db_session.get(AnalysisRun, run.id)
            assert reloaded_run is not None
            # MUST NOT OVERWRITE PRIMARY REVIEW ID!
            assert reloaded_run.github_review_id == primary_review_id
            assert reloaded_run.reanalysis_needed is False

            reloaded_dl = db_session.get(DeadLetterLog, dl.id)
            assert reloaded_dl is not None
            assert reloaded_dl.resolved is True

            reloaded_unposted = db_session.get(DBFinding, unposted.id)
            assert reloaded_unposted is not None
            assert reloaded_unposted.is_posted is True

    def test_injected_llm_failure_exercises_real_failure_counter_and_trips_at_threshold(self) -> None:
        """Single injected failure increments counter but keeps breaker CLOSED; 5 failures trip to OPEN."""
        from codepulse.persistence.database import get_redis_client
        from codepulse.analysis.circuit_breaker import CircuitBreaker
        from codepulse.worker.tasks import analyze_llm_task

        redis_client = get_redis_client()
        breaker = CircuitBreaker(redis_client, name="gemini")
        redis_client.delete(breaker.state_key, breaker.failures_key, breaker.opened_at_key)

        chunk = make_chunk_dict()
        with patch.dict(os.environ, {"MOCK_LLM": "true", "MOCK_LLM_FAILURE": "true"}):
            # 1st failure: increments counter, breaker is STILL CLOSED
            res1 = analyze_llm_task([chunk], "org/repo", "python", str(uuid.uuid4()))
            assert res1["llm_degraded"] is True
            assert res1["error"] == "Simulated Gemini API failure (injected)"
            assert breaker.get_state() == "CLOSED"
            assert int(redis_client.get(breaker.failures_key) or 0) == 1

            # Failures 2, 3, 4: still CLOSED
            for expected_count in [2, 3, 4]:
                analyze_llm_task([chunk], "org/repo", "python", str(uuid.uuid4()))
                assert breaker.get_state() == "CLOSED"
                assert int(redis_client.get(breaker.failures_key) or 0) == expected_count

            # 5th failure: trips breaker to OPEN
            analyze_llm_task([chunk], "org/repo", "python", str(uuid.uuid4()))
            assert breaker.get_state() == "OPEN"

            # 6th attempt: intercepted at step 3 by circuit breaker check
            res6 = analyze_llm_task([chunk], "org/repo", "python", str(uuid.uuid4()))
            assert res6["llm_degraded"] is True
            assert res6["error"] == "Circuit breaker OPEN"


class TestScanUnpostedReviews:
    """Verifies §6.4 & §10.2 Branch F periodic recovery of unposted reviews older than 15 minutes."""

    @pytest.fixture(autouse=True)
    def clean_unposted(self, db_session: Session) -> None:
        """Mark existing runs as posted so tests have clean isolated state."""
        db_session.query(AnalysisRun).filter(AnalysisRun.review_posted_at.is_(None)).update(
            {"review_posted_at": datetime.now(timezone.utc)}
        )
        db_session.commit()

    def test_scan_unposted_reviews_ignores_recent_runs(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """Runs created within the 15-minute cutoff window are ignored."""
        from codepulse.worker.tasks import scan_unposted_reviews
        repo, run = test_repo_and_run
        run.status = "completed"
        run.review_posted_at = None
        run.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db_session.commit()

        count = scan_unposted_reviews(cutoff_minutes=15)
        assert count == 0
        db_session.refresh(run)
        assert run.review_posted_at is None

    def test_scan_unposted_reviews_reposts_older_unposted_run(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """Completed runs older than 15 minutes with Branch F dead letters are posted idempotently."""
        from codepulse.models.tables import DeadLetterLog
        from codepulse.worker.tasks import scan_unposted_reviews
        repo, run = test_repo_and_run
        run.status = "completed"
        run.review_posted_at = None
        run.head_sha = "1" * 40
        run.created_at = datetime.now(timezone.utc) - timedelta(minutes=20)

        # Create finding with is_posted=False
        finding = DBFinding(
            id=uuid.uuid4(),
            analysis_run_id=run.id,
            file_path="src/app.py",
            line_start=1,
            line_end=1,
            severity="critical",
            category="A03",
            title="SQLi",
            explanation="Unsanitized query",
            remediation="Use params",
            confidence="high",
            source="ast",
            is_posted=False,
        )
        db_session.add(finding)

        # Create dead_letter_log row with Branch F payload
        dl = DeadLetterLog(
            task_name="tasks.post_review_to_github",
            task_id=uuid.uuid4(),
            task_args={
                "analysis_run_id": str(run.id),
                "review_payload": {
                    "event": "COMMENT",
                    "body": "## Re-posted Review Summary",
                    "comments": [],
                },
            },
            exception_type="RuntimeError",
            exception_message="GitHub 503 Service Unavailable",
            traceback="Traceback...",
            retry_count=5,
            resolved=False,
        )
        db_session.add(dl)
        db_session.commit()

        with patch("codepulse.worker.tasks.get_github_poster") as mock_poster_factory:
            mock_poster = MagicMock()
            mock_poster.post_review.return_value = {"id": 77665544}
            mock_poster_factory.return_value = mock_poster

            # Run periodic sweep
            count = scan_unposted_reviews(cutoff_minutes=15)
            assert count == 1

            mock_poster.post_review.assert_called_once()
            args = mock_poster.post_review.call_args[0]
            assert args[2] == run.pull_request_number
            assert args[3]["body"] == "## Re-posted Review Summary"

        db_session.expire_all()
        reloaded_run = db_session.get(AnalysisRun, run.id)
        assert reloaded_run is not None
        assert reloaded_run.review_posted_at is not None
        assert reloaded_run.github_review_id == 77665544

        reloaded_dl = db_session.get(DeadLetterLog, dl.id)
        assert reloaded_dl is not None
        assert reloaded_dl.resolved is True

        reloaded_finding = db_session.get(DBFinding, finding.id)
        assert reloaded_finding is not None
        assert reloaded_finding.is_posted is True

        # Second sweep must be idempotent and find 0
        count2 = scan_unposted_reviews(cutoff_minutes=15)
        assert count2 == 0

    def test_scan_unposted_reviews_skips_when_superseded(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """When PR head SHA has moved, unposted review is marked resolved without posting."""
        from codepulse.models.tables import DeadLetterLog
        from codepulse.worker.tasks import scan_unposted_reviews
        repo, run = test_repo_and_run
        run.status = "completed"
        run.review_posted_at = None
        run.head_sha = "1" * 40
        run.created_at = datetime.now(timezone.utc) - timedelta(minutes=25)

        dl = DeadLetterLog(
            task_name="tasks.post_review_to_github",
            task_id=uuid.uuid4(),
            task_args={
                "analysis_run_id": str(run.id),
                "review_payload": {"event": "COMMENT", "body": "Summary", "comments": []},
            },
            exception_type="RuntimeError",
            exception_message="GitHub timeout",
            traceback="Traceback...",
            retry_count=5,
            resolved=False,
        )
        db_session.add(dl)
        db_session.commit()

        with patch("codepulse.worker.tasks.get_diff_fetcher") as mock_df_factory:
            mock_df = MagicMock()
            mock_df.fetch_pr_head_sha.return_value = "2" * 40  # Head SHA moved
            mock_df_factory.return_value = mock_df

            with patch("codepulse.worker.tasks.get_github_poster") as mock_poster_factory:
                mock_poster = MagicMock()
                mock_poster_factory.return_value = mock_poster

                count = scan_unposted_reviews(cutoff_minutes=15)
                assert count == 0
                mock_poster.post_review.assert_not_called()

        db_session.expire_all()
        reloaded_dl = db_session.get(DeadLetterLog, dl.id)
        assert reloaded_dl is not None
        assert reloaded_dl.resolved is True
        reloaded_run = db_session.get(AnalysisRun, run.id)
        assert reloaded_run is not None
        assert reloaded_run.review_posted_at is None

