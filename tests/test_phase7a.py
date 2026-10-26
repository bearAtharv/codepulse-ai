"""Tests for Phase 7a: Pass-by-reference pipeline, retries, dead-letter handling, and admin retry.

Covers:
- Branch C: GitHub diff fetch failure, retries, dead-letter logging, and terminal status (§10.2).
- Branch F: Review posting failure, retries, durable dead-letter review payload, findings preserved (§10.2).
- Admin retry endpoint: POST /admin/retry-posting/{analysis_run_id} authentication, error states, and recovery (§3.5.4).
- Branch G: PostgreSQL persistence failure, Redis fallback, and recovery process (§10.2).
- Branch H: Celery configuration for at-least-once delivery (task_acks_late, visibility_timeout=300).
- Pass-by-reference: Redis caching of diffs and review payloads with TTL (§3.7.2).
- Worker log privacy: Zero customer source code in logs.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from codepulse.aggregation.models import Finding
from codepulse.config import get_settings
from codepulse.ingestion.app import app
from codepulse.models.tables import AnalysisRun, DeadLetterLog, Finding as DBFinding, Repository
from codepulse.persistence.database import (
    get_db_session,
    get_payload_ref,
    get_redis_client,
    save_payload_ref,
)
from codepulse.worker.celery_app import celery_app
from codepulse.worker.tasks import (
    FETCH_PR_DIFF_BACKOFF,
    POST_REVIEW_BACKOFF,
    aggregate_findings,
    fetch_pr_diff,
    persist_results,
    post_review_to_github,
    recover_pending_persistence,
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
    """Helper fixture to insert a test repository and analysis run."""
    run_uuid = uuid.uuid4()
    repo_id = int(run_uuid.int % 1_000_000_000)
    repo = Repository(
        id=repo_id,
        github_id=repo_id,
        full_name=f"test-owner/test-repo-{run_uuid.hex[:6]}",
        installation_id=12345,
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    run = AnalysisRun(
        id=run_uuid,
        repository_id=repo.id,
        pull_request_number=42,
        head_sha="a" * 40,
        base_sha="b" * 40,
        pr_author="test-author",
        status="running",
        webhook_received_at=datetime.now(timezone.utc),
    )
    db_session.add(run)
    db_session.commit()
    return repo, run


class TestPhase7aCeleryConfiguration:
    """Verifies §6.2 and §10.2 Branch H processing guarantees in Celery config."""

    def test_celery_task_acks_late_and_visibility_timeout(self) -> None:
        """Celery broker must have task_acks_late=True, worker_prefetch_multiplier=1, and visibility_timeout=300."""
        assert celery_app.conf.task_acks_late is True
        assert celery_app.conf.worker_prefetch_multiplier == 1
        assert celery_app.conf.broker_transport_options.get("visibility_timeout") == 300

    def test_celery_task_time_limits_annotations(self) -> None:
        """Task timeouts match §3.5.5 configuration."""
        annotations = celery_app.conf.task_annotations
        assert annotations["tasks.fetch_pr_diff"] == {"soft_time_limit": 30, "time_limit": 45}
        assert annotations["tasks.preprocess_and_chunk"] == {"soft_time_limit": 10, "time_limit": 15}
        assert annotations["tasks.analyze_ast"] == {"soft_time_limit": 5, "time_limit": 8}
        assert annotations["tasks.analyze_llm"] == {"soft_time_limit": 15, "time_limit": 20}
        assert annotations["tasks.aggregate_findings"] == {"soft_time_limit": 5, "time_limit": 8}
        assert annotations["tasks.post_review_to_github"] == {"soft_time_limit": 30, "time_limit": 45}
        assert annotations["tasks.persist_results"] == {"soft_time_limit": 10, "time_limit": 15}

    def test_branch_h_task_redelivery_idempotency(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        """When an unacknowledged task is redelivered (Branch H), handlers must be idempotent."""
        repo, run = test_repo_and_run
        payload = {
            "context": {
                "installation_id": repo.installation_id,
                "repository_full_name": repo.full_name,
                "pull_request_number": run.pull_request_number,
                "head_sha": run.head_sha,
                "analysis_run_id": str(run.id),
                "webhook_received_at": datetime.now(timezone.utc).isoformat(),
            },
            "findings": [
                {
                    "file_path": "src/app.py",
                    "line_start": 1,
                    "line_end": 1,
                    "severity": "high",
                    "category": "A03",
                    "title": "Idempotent Finding",
                    "explanation": "Test",
                    "remediation": "Fix",
                    "confidence": "high",
                    "source": "ast",
                }
            ],
            "files_analyzed": 1,
            "chunks_total": 1,
            "chunks_completed": 1,
            "analysis_duration_ms": 100,
            "github_review_id": 12345,
            "review_posted_at": datetime.now(timezone.utc).isoformat(),
            "llm_usages": [],
        }

        # First delivery
        res1 = persist_results(payload)
        assert res1["status"] == "completed"

        # Redelivery after crash
        res2 = persist_results(payload)
        assert res2["status"] == "completed"

        # Confirm no duplicate findings created in DB
        findings = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
        assert len(findings) == 1
        assert findings[0].title == "Idempotent Finding"


class TestPhase7aPassByReference:
    """Verifies Redis payload reference storage and passing (Section 3.7.2)."""

    def test_redis_payload_reference_round_trip(self) -> None:
        """Data can be saved and retrieved by key in Redis with TTL."""
        test_key = f"test:ref:{uuid.uuid4()}"
        data = {"hello": "world", "items": [1, 2, 3]}
        save_payload_ref(test_key, data, ttl=60)

        retrieved = get_payload_ref(test_key)
        assert retrieved == data

        # Test TTL
        client = get_redis_client()
        ttl = client.ttl(test_key)
        assert 0 < ttl <= 60

    def test_aggregate_findings_stores_review_payload_reference(self) -> None:
        """aggregate_findings stores review_payload in Redis and returns review_ref."""
        run_id = str(uuid.uuid4())
        context = {
            "installation_id": 1,
            "repository_full_name": "owner/repo",
            "pull_request_number": 1,
            "head_sha": "a" * 40,
            "analysis_run_id": run_id,
        }
        res = aggregate_findings(
            [],
            context=context,
            diff_text="--- a/test.py\n+++ b/test.py\n@@ -0,0 +1 @@\n+x = 1\n",
            files_analyzed=1,
            chunks_total=0,
        )

        assert res["review_ref"] == f"review_payload:{run_id}"
        # Validate that the payload is in Redis
        stored_payload = get_payload_ref(f"review_payload:{run_id}")
        assert stored_payload is not None
        assert stored_payload["event"] == "COMMENT"
        assert "CodePulse AI" in stored_payload["body"]


class TestPhase7aBranchC:
    """Verifies Branch C: GitHub API diff fetch failure (§10.2)."""

    def test_diff_fetch_retry_exhaustion_marks_failed_and_dead_letters(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        repo, run = test_repo_and_run
        payload = {
            "installation_id": repo.installation_id,
            "repository_full_name": repo.full_name,
            "pull_request_number": run.pull_request_number,
            "head_sha": run.head_sha,
            "base_sha": run.base_sha,
            "pr_author": run.pr_author,
            "webhook_received_at": datetime.now(timezone.utc).isoformat(),
            "analysis_run_id": str(run.id),
        }

        # Simulate failure injection
        with patch.dict(os.environ, {"MOCK_DIFF_FETCH_FAILURE": "true"}):
            with pytest.raises(RuntimeError, match="Simulated GitHub diff fetch failure"):
                fetch_pr_diff(payload)

        # Confirm run status updated to terminal 'failed' with error message
        db_session.expire_all()
        reloaded = db_session.get(AnalysisRun, run.id)
        assert reloaded is not None
        assert reloaded.status == "failed"
        assert "GitHub API unavailable" in (reloaded.error_message or "")

        # Confirm dead_letter_log row created
        stmt = select(DeadLetterLog).where(
            DeadLetterLog.task_name == "tasks.fetch_pr_diff",
            DeadLetterLog.resolved == False,  # noqa: E712
        )
        dl_entries = db_session.execute(stmt).scalars().all()
        matching = [e for e in dl_entries if e.task_args.get("analysis_run_id") == str(run.id)]
        assert len(matching) >= 1
        assert matching[0].exception_type == "RuntimeError"


class TestPhase7aBranchFAndAdminRetry:
    """Verifies Branch F (posting failure) and the Admin Retry Endpoint (§3.5.4, §10.2)."""

    def test_branch_f_exhaustion_persists_review_in_dead_letter_and_keeps_findings(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        repo, run = test_repo_and_run
        run_id = str(run.id)

        finding = Finding(
            file_path="src/app.py",
            line_start=1,
            line_end=1,
            severity="critical",
            category="A03",
            title="SQL Injection Exploit",
            explanation="Dangerous query string",
            remediation="Parametrize query",
            confidence="high",
            source="llm",
        )

        review_payload = {
            "event": "COMMENT",
            "body": "CodePulse Review Summary: 1 finding",
            "comments": [
                {
                    "path": "src/app.py",
                    "line": 1,
                    "side": "RIGHT",
                    "body": "🔴 **Critical**: SQL Injection Exploit",
                }
            ],
        }

        data = {
            "context": {
                "installation_id": repo.installation_id,
                "repository_full_name": repo.full_name,
                "pull_request_number": run.pull_request_number,
                "head_sha": run.head_sha,
                "analysis_run_id": run_id,
                "webhook_received_at": datetime.now(timezone.utc).isoformat(),
            },
            "findings": [finding.to_dict()],
            "review_payload": review_payload,
            "files_analyzed": 1,
            "chunks_total": 1,
            "chunks_completed": 1,
            "analysis_duration_ms": 100,
            "llm_usages": [],
        }

        # 1. Run post_review_to_github with failure injection
        with patch.dict(os.environ, {"MOCK_POSTING_FAILURE": "true"}):
            posted_data = post_review_to_github(data)

        # Confirm post_review_to_github did NOT crash, but marked review unposted
        assert posted_data["github_review_id"] is None
        assert posted_data["review_posted_at"] is None
        assert "Simulated GitHub review posting failure" in posted_data["posting_error"]

        # Confirm DeadLetterLog has the durable review payload
        stmt = select(DeadLetterLog).where(
            DeadLetterLog.task_name == "tasks.post_review_to_github",
            DeadLetterLog.resolved == False,  # noqa: E712
        )
        dl_entries = db_session.execute(stmt).scalars().all()
        matching = [e for e in dl_entries if e.task_args.get("analysis_run_id") == run_id]
        assert len(matching) == 1
        assert matching[0].task_args["review_payload"] == review_payload

        # 2. Run persist_results: findings must STILL be persisted
        persist_res = persist_results(posted_data)
        assert persist_res["status"] == "completed"

        db_session.expire_all()
        reloaded_run = db_session.get(AnalysisRun, run.id)
        assert reloaded_run is not None
        assert reloaded_run.status == "completed"
        assert reloaded_run.review_posted_at is None
        assert reloaded_run.github_review_id is None

        db_findings = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
        assert len(db_findings) == 1
        assert db_findings[0].title == "SQL Injection Exploit"

    def test_admin_retry_auth_and_recovery(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        repo, run = test_repo_and_run
        run_id = str(run.id)
        client = TestClient(app)

        # 1. Disabled when ADMIN_API_KEY is unset -> 503
        with patch.object(get_settings(), "admin_api_key", None):
            res = client.post(
                f"/admin/retry-posting/{run_id}",
                headers={"Authorization": "Bearer some-key"},
            )
            assert res.status_code == 503
            assert "disabled" in res.json()["detail"].lower()

        # 2. When ADMIN_API_KEY is configured:
        with patch.object(get_settings(), "admin_api_key", "valid_secret_key_12345"):
            # 2a. Missing Authorization header -> 401
            res = client.post(f"/admin/retry-posting/{run_id}")
            assert res.status_code == 401
            assert "Bearer" in res.json()["detail"]

            # 2b. Wrong bearer token -> 401
            res = client.post(
                f"/admin/retry-posting/{run_id}",
                headers={"Authorization": "Bearer wrong-key"},
            )
            assert res.status_code == 401
            assert "Invalid" in res.json()["detail"]

        # 3. Refuse dev keys in production -> 500
        with patch.object(get_settings(), "environment", "production"):
            with patch.object(get_settings(), "admin_api_key", "dev_admin_key_not_for_production"):
                res = client.post(
                    f"/admin/retry-posting/{run_id}",
                    headers={"Authorization": "Bearer dev_admin_key_not_for_production"},
                )
                assert res.status_code == 500
                assert "insecure" in res.json()["detail"].lower()

        # 4. Wrong bearer token -> 401
        with patch.object(get_settings(), "admin_api_key", "valid_secret_key_12345"):
            res = client.post(
                f"/admin/retry-posting/{run_id}",
                headers={"Authorization": "Bearer wrong-key"},
            )
            assert res.status_code == 401
            assert "Invalid" in res.json()["detail"]

        # 5. Successful retry with valid token:
        # First ensure a DeadLetterLog entry exists with durable review payload
        review_payload = {
            "event": "COMMENT",
            "body": "Durable review summary",
            "comments": [{"path": "src/app.py", "line": 1, "side": "RIGHT", "body": "Inline"}],
        }
        dl = DeadLetterLog(
            task_name="tasks.post_review_to_github",
            task_id=uuid.uuid4(),
            task_args={"analysis_run_id": run_id, "review_payload": review_payload},
            exception_type="RuntimeError",
            exception_message="GitHub 500",
            traceback="mock tb",
            retry_count=5,
            resolved=False,
        )
        db_session.add(dl)
        db_session.commit()

        with patch.object(get_settings(), "admin_api_key", "valid_secret_key_12345"):
            res = client.post(
                f"/admin/retry-posting/{run_id}",
                headers={"Authorization": "Bearer valid_secret_key_12345"},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "success"
            assert data["github_review_id"] is not None

        # Verify DB updated: review_posted_at set, dead_letter marked resolved
        db_session.expire_all()
        reloaded_run = db_session.get(AnalysisRun, run.id)
        assert reloaded_run is not None
        assert reloaded_run.review_posted_at is not None
        assert reloaded_run.github_review_id == data["github_review_id"]

        reloaded_dl = db_session.get(DeadLetterLog, dl.id)
        assert reloaded_dl is not None
        assert reloaded_dl.resolved is True


class TestPhase7aBranchGAndPersistenceRecovery:
    """Verifies Branch G: PostgreSQL persistence failure fallback and recovery (§10.2)."""

    def test_persist_results_fallback_to_redis_and_recovery(
        self, db_session: Session, test_repo_and_run: tuple[Repository, AnalysisRun]
    ) -> None:
        repo, run = test_repo_and_run
        run_id = str(run.id)

        finding = Finding(
            file_path="src/main.py",
            line_start=10,
            line_end=10,
            severity="high",
            category="A01",
            title="Access Control Bypass",
            explanation="Missing auth check",
            remediation="Add authorization header check",
            confidence="high",
            source="ast",
        )

        data = {
            "context": {
                "installation_id": repo.installation_id,
                "repository_full_name": repo.full_name,
                "pull_request_number": run.pull_request_number,
                "head_sha": run.head_sha,
                "analysis_run_id": run_id,
                "webhook_received_at": datetime.now(timezone.utc).isoformat(),
            },
            "findings": [finding.to_dict()],
            "files_analyzed": 1,
            "chunks_total": 1,
            "chunks_completed": 1,
            "analysis_duration_ms": 250,
            "github_review_id": 999888,
            "review_posted_at": datetime.now(timezone.utc).isoformat(),
            "llm_usages": [
                {
                    "model_version": "gemini-3.7-flash",
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "latency_ms": 120,
                    "cache_hit": False,
                }
            ],
        }

        # 1. Simulate PostgreSQL persistence failure injection
        with patch.dict(os.environ, {"MOCK_PERSIST_FAILURE": "true"}):
            fallback_res = persist_results(data)

        assert fallback_res["status"] == "fallback_redis"
        assert fallback_res["analysis_run_id"] == run_id

        # Verify findings are held in Redis
        stored_fallback = get_payload_ref(f"dead_letter:persist:{run_id}")
        assert stored_fallback is not None
        assert len(stored_fallback["findings"]) == 1
        assert stored_fallback["findings"][0]["title"] == "Access Control Bypass"

        # 2. Run recovery process
        redis_client = get_redis_client()
        recovered_count = recover_pending_persistence(redis_client, db_session)
        assert recovered_count >= 1

        # Verify DB is now updated
        db_session.expire_all()
        reloaded_run = db_session.get(AnalysisRun, run.id)
        assert reloaded_run is not None
        assert reloaded_run.status == "completed"
        assert reloaded_run.github_review_id == 999888

        findings_in_db = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
        assert len(findings_in_db) == 1
        assert findings_in_db[0].title == "Access Control Bypass"


class TestPhase7aWorkerLogPrivacy:
    """Verifies that worker logs contain ZERO customer source code or diff hunks (§7.1)."""

    def test_worker_logs_contain_zero_source_code(self, caplog: pytest.LogCaptureFixture) -> None:
        """Pipeline logging must record only metadata (IDs, file names, counts), not code snippets."""
        caplog.set_level(logging.INFO)

        secret_source_line = "eval(user_input_from_untrusted_source)"
        run_id = str(uuid.uuid4())
        context = {
            "installation_id": 1,
            "repository_full_name": "owner/repo",
            "pull_request_number": 1,
            "head_sha": "c" * 40,
            "analysis_run_id": run_id,
        }

        diff_text = f"--- a/src/app.py\n+++ b/src/app.py\n@@ -0,0 +1 @@\n+{secret_source_line}\n"

        # Run aggregate_findings
        aggregate_findings(
            [],
            context=context,
            diff_text=diff_text,
            files_analyzed=1,
            chunks_total=1,
        )

        all_logs = caplog.text
        # Assert secret source code is NOT present in any log record
        assert "user_input_from_untrusted_source" not in all_logs
        assert secret_source_line not in all_logs
        # Metadata IS present
        assert run_id in all_logs
        assert "owner/repo" in all_logs
