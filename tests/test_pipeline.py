"""Tests for Phase 6b: Celery task orchestration and worker pipeline.

Covers:
1. Unit tests with mocks for each pipeline task (orchestrate, fetch, chunk, ast, llm,
   aggregate, post, persist).
2. Category normalization fallback preserving raw_category and logging a warning.
3. PostgreSQL-backed integration test of the full chain using the mock diff fixture
   in eager mode (skips cleanly if Postgres is unreachable, strictly no SQLite).
4. Verification that a GitHub posting failure still results in persisted findings (§10.2 Branch F).
5. Verification that an all-filtered diff terminates cleanly with status='skipped' (§3.2.2).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from codepulse.aggregation.models import Finding, normalize_category
from codepulse.analysis.heuristics.base import ASTFinding
from codepulse.config import get_settings
from codepulse.ingestion.diff_fetcher import MockDiffFetcher, PRFile
from codepulse.ingestion.preprocessor import AnalysisChunk
from codepulse.models.tables import AnalysisRun, Finding as DBFinding, LlmUsageLog, Repository
from codepulse.worker.celery_app import celery_app
from codepulse.worker.tasks import (
    aggregate_findings,
    analyze_ast_task,
    analyze_llm_task,
    fetch_pr_diff,
    orchestrate_pr_analysis,
    persist_results,
    post_review_to_github,
    preprocess_and_chunk,
)


@pytest.fixture
def db_session():
    """Yield a database session connected to PostgreSQL, or skip cleanly if unreachable."""
    settings = get_settings()
    try:
        engine = create_engine(settings.database_url, connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        pytest.skip(f"Docker PostgreSQL unreachable at {settings.database_url}: {exc}")

    session_factory = sessionmaker(bind=engine)
    session: Session = session_factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _create_db_run(db: Session) -> tuple[Repository, AnalysisRun]:
    """Helper to insert a Repository and AnalysisRun row for integration tests."""
    gh_id = int(uuid.uuid4().int % 1_000_000_000)
    repo = Repository(
        github_id=gh_id,
        full_name=f"test-owner/test-repo-{gh_id}",
        installation_id=98765,
        default_branch="main",
        primary_language="Python",
    )
    db.add(repo)
    db.flush()

    run = AnalysisRun(
        id=uuid.uuid4(),
        repository_id=repo.id,
        pull_request_number=1,
        head_sha="1234567890abcdef1234567890abcdef12345678",
        base_sha="abcdef1234567890abcdef1234567890abcdef12",
        pr_author="test-coder",
        status="pending",
        webhook_received_at=datetime.now(timezone.utc),
    )
    db.add(run)
    db.commit()
    return repo, run


# ── 1. Category Normalization Fallback Test ─────────────────────────────


class TestCategoryNormalizationFallback:
    """Verifies that unknown category fallback preserves raw_category and logs a warning."""

    def test_unknown_category_fallback_preserves_raw_and_warns(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        raw = "CompletelyUnrecognizedVulnerabilityPattern"
        with caplog.at_level(logging.WARNING):
            norm = normalize_category(raw)

        assert norm == "A04"
        assert norm.raw_category == raw
        assert any("could not be matched" in record.message for record in caplog.records)

    def test_finding_from_ast_finding_preserves_raw_category_on_unknown(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        ast_f = ASTFinding(
            rule_id="CUSTOM-999",
            file_path="src/custom.py",
            line_start=10,
            line_end=10,
            severity="medium",
            category="CustomUnknownPattern",
            title="Custom Warning",
            explanation="Something unusual",
            remediation="Check it",
            confidence="low",
        )
        with caplog.at_level(logging.WARNING):
            f = Finding.from_ast_finding(ast_f)

        assert f.category == "A04"
        assert f.raw_category == "CustomUnknownPattern"


# ── 2. Unit Tests for Pipeline Tasks (with Mocks) ──────────────────────


class TestPipelineTaskUnits:
    """Isolated unit tests for each worker task's behavior."""

    @patch("codepulse.worker.tasks.update_analysis_run_status")
    @patch("codepulse.worker.tasks.chain")
    def test_orchestrate_pr_analysis(
        self,
        mock_chain: MagicMock,
        mock_update: MagicMock,
    ) -> None:
        mock_workflow = MagicMock()
        mock_chain.return_value = mock_workflow

        res = orchestrate_pr_analysis(
            installation_id=1,
            repository_full_name="owner/repo",
            pull_request_number=42,
            head_sha="a" * 40,
            base_sha="b" * 40,
            pr_author="alice",
            webhook_received_at="2026-10-24T12:00:00+00:00",
            analysis_run_id=str(uuid.uuid4()),
        )

        assert res["status"] == "running"
        mock_workflow.apply_async.assert_called_once()
        mock_update.assert_called_once()

    def test_fetch_pr_diff(self) -> None:
        payload = {
            "installation_id": 123,
            "repository_full_name": "owner/repo",
            "pull_request_number": 1,
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "pr_author": "alice",
            "webhook_received_at": "2026-10-24T12:00:00+00:00",
            "analysis_run_id": str(uuid.uuid4()),
        }
        res = fetch_pr_diff(payload)
        assert "files" in res
        assert "context" in res
        assert len(res["files"]) == 5  # MockDiffFetcher default files

    @patch("codepulse.worker.tasks.update_analysis_run_status")
    def test_preprocess_and_chunk_all_filtered_marks_skipped(
        self,
        mock_update: MagicMock,
    ) -> None:
        data = {
            "files": [
                {
                    "filename": "poetry.lock",
                    "status": "modified",
                    "patch": "@@ -1 +1 @@",
                    "additions": 1,
                    "deletions": 1,
                    "changes": 2,
                }
            ],
            "context": {
                "installation_id": 1,
                "repository_full_name": "owner/repo",
                "pull_request_number": 1,
                "head_sha": "a" * 40,
                "analysis_run_id": str(uuid.uuid4()),
            },
        }
        res = preprocess_and_chunk(data)
        assert res["status"] == "skipped"
        mock_update.assert_called_once()

    @patch("codepulse.worker.tasks.chord")
    def test_preprocess_and_chunk_dispatches_chord(self, mock_chord: MagicMock) -> None:
        data = {
            "files": [
                {
                    "filename": "src/app.py",
                    "status": "added",
                    "patch": "@@ -0,0 +1,2 @@\n+data = eval(x)\n+print(data)\n",
                    "additions": 2,
                    "deletions": 0,
                    "changes": 2,
                }
            ],
            "context": {
                "installation_id": 1,
                "repository_full_name": "owner/repo",
                "pull_request_number": 1,
                "head_sha": "a" * 40,
                "analysis_run_id": str(uuid.uuid4()),
            },
        }
        mock_callback_chain = MagicMock()
        mock_chord.return_value = mock_callback_chain

        res = preprocess_and_chunk(data)
        assert res["status"] == "dispatched"
        assert res["chunks_total"] >= 1
        mock_chord.assert_called_once()

    def test_analyze_ast_task(self) -> None:
        chunk = AnalysisChunk(
            file_path="src/vuln.py",
            language="python",
            source_code="data = eval(user_input)\n",
            diff_text="@@ -0,0 +1 @@\n+data = eval(user_input)\n",
            hunk_header="@@ -0,0 +1 @@",
            modified_lines=[1],
        )
        res = analyze_ast_task(chunk.to_dict())
        assert res["type"] == "ast"
        assert len(res["findings"]) >= 1
        assert res["findings"][0]["category"] == "A03"

    def test_analyze_llm_task(self) -> None:
        chunk = AnalysisChunk(
            file_path="src/app.py",
            language="python",
            source_code="data = eval(user_input)\n",
            diff_text="@@ -0,0 +1 @@\n+data = eval(user_input)\n",
            hunk_header="@@ -0,0 +1 @@",
            modified_lines=[1],
        )
        res = analyze_llm_task([chunk.to_dict()], "owner/repo", "python", str(uuid.uuid4()))
        assert res["type"] == "llm"
        assert "findings" in res
        assert "usage" in res
        assert res["usage"]["cache_hit"] is False

    def test_aggregate_findings_task(self) -> None:
        f_ast = Finding(
            file_path="src/app.py",
            line_start=1,
            line_end=1,
            severity="critical",
            category="A03",
            title="AST SQLi",
            explanation="Unchecked input",
            remediation="Fix",
            confidence="high",
            source="ast",
        ).to_dict()

        f_llm = Finding(
            file_path="src/app.py",
            line_start=1,
            line_end=1,
            severity="critical",
            category="A03",
            title="LLM SQLi",
            explanation="Potential injection",
            remediation="Fix",
            confidence="medium",
            source="llm",
        ).to_dict()

        results = [
            {"type": "ast", "findings": [f_ast]},
            {"type": "llm", "findings": [f_llm], "usage": {"model_version": "gemini-3.7-flash", "input_tokens": 10, "output_tokens": 5, "latency_ms": 100}},
        ]
        context = {
            "installation_id": 1,
            "repository_full_name": "owner/repo",
            "pull_request_number": 1,
            "head_sha": "a" * 40,
            "analysis_run_id": str(uuid.uuid4()),
        }
        res = aggregate_findings(
            results,
            context=context,
            diff_text="--- a/src/app.py\n+++ b/src/app.py\n@@ -0,0 +1 @@\n+eval(input)\n",
            files_analyzed=1,
            chunks_total=1,
        )

        assert "findings" in res
        assert "review_payload" in res
        assert len(res["findings"]) == 1
        assert res["findings"][0]["source"] == "merged"

    def test_post_review_to_github_success(self) -> None:
        data = {
            "context": {
                "installation_id": 1,
                "repository_full_name": "owner/repo",
                "pull_request_number": 1,
            },
            "review_payload": {"event": "COMMENT", "body": "test", "comments": []},
        }
        res = post_review_to_github(data)
        assert res.get("github_review_id") is not None
        assert res.get("review_posted_at") is not None

    def test_post_review_to_github_failure_preserves_data(self) -> None:
        """Posting failure must not discard findings or fail the pipeline (§10.2 Branch F)."""
        data = {
            "context": {
                "installation_id": 1,
                "repository_full_name": "owner/repo",
                "pull_request_number": 1,
            },
            "findings": [{"title": "critical vuln", "line_start": 1}],
            "review_payload": {"event": "COMMENT", "body": "test", "comments": []},
        }
        with patch("codepulse.worker.tasks.get_github_poster") as mock_get_poster:
            mock_poster = MagicMock()
            mock_poster.post_review.side_effect = RuntimeError("GitHub API 500 Internal Error")
            mock_get_poster.return_value = mock_poster

            res = post_review_to_github(data)

            assert res.get("github_review_id") is None
            assert res.get("review_posted_at") is None
            assert "posting_error" in res
            assert len(res["findings"]) == 1


# ── 3. PostgreSQL-Backed Full Pipeline Integration Tests ────────────────


class TestPipelinePostgreSQLIntegration:
    """Full-pipeline integration tests against live PostgreSQL.

    Skips cleanly if PostgreSQL is unreachable. Strictly no SQLite.
    Note: Celery task_always_eager=True executes tasks synchronously in-process
    and validates data flow, schema persistence, and error handling, but does
    not test distributed Redis chord barrier synchronization.
    """

    def test_full_pipeline_postgres_eager(self, db_session: Session) -> None:
        """Full end-to-end execution of orchestrate_pr_analysis against PostgreSQL."""
        repo, run = _create_db_run(db_session)

        # Configure Celery to run eagerly in this test
        celery_app.conf.update(task_always_eager=True)

        res = orchestrate_pr_analysis.apply_async(
            kwargs={
                "installation_id": repo.installation_id,
                "repository_full_name": repo.full_name,
                "pull_request_number": run.pull_request_number,
                "head_sha": run.head_sha,
                "base_sha": run.base_sha,
                "pr_author": run.pr_author,
                "webhook_received_at": datetime.now(timezone.utc).isoformat(),
                "analysis_run_id": str(run.id),
            }
        )

        db_session.expire_all()
        reloaded = db_session.get(AnalysisRun, run.id)
        assert reloaded is not None
        assert reloaded.status == "completed"
        assert reloaded.files_analyzed == 3  # MockDiffFetcher: app.py, index.js, clean.py
        assert reloaded.chunks_total >= 3
        assert reloaded.total_findings >= 1
        assert reloaded.github_review_id is not None
        assert reloaded.review_posted_at is not None

        # Verify findings persisted in PostgreSQL
        findings = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
        assert len(findings) == reloaded.total_findings
        assert any(f.source == "merged" for f in findings)

        # Verify LLM telemetry recorded
        usages = db_session.query(LlmUsageLog).filter(LlmUsageLog.analysis_run_id == run.id).all()
        assert len(usages) >= 1
        assert all(u.cache_hit is False for u in usages)

    def test_posting_failure_still_persists_findings_in_postgres(self, db_session: Session) -> None:
        """Posting failure must leave findings persisted and review_posted_at=None (§10.2 Branch F)."""
        repo, run = _create_db_run(db_session)
        celery_app.conf.update(task_always_eager=True)

        with patch("codepulse.worker.tasks.get_github_poster") as mock_get_poster:
            mock_poster = MagicMock()
            mock_poster.post_review.side_effect = RuntimeError("GitHub 503 Service Unavailable")
            mock_get_poster.return_value = mock_poster

            orchestrate_pr_analysis.apply_async(
                kwargs={
                    "installation_id": repo.installation_id,
                    "repository_full_name": repo.full_name,
                    "pull_request_number": run.pull_request_number,
                    "head_sha": run.head_sha,
                    "base_sha": run.base_sha,
                    "pr_author": run.pr_author,
                    "webhook_received_at": datetime.now(timezone.utc).isoformat(),
                    "analysis_run_id": str(run.id),
                }
            )

        db_session.expire_all()
        reloaded = db_session.get(AnalysisRun, run.id)
        assert reloaded is not None
        assert reloaded.status == "completed"
        assert reloaded.github_review_id is None
        assert reloaded.review_posted_at is None
        assert reloaded.total_findings >= 1

        # Findings are NOT lost!
        findings = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
        assert len(findings) >= 1

    def test_all_filtered_diff_ends_with_status_skipped_in_postgres(self, db_session: Session) -> None:
        """When all diff files are excluded (e.g. lockfiles), status must be 'skipped' (§3.2.2)."""
        repo, run = _create_db_run(db_session)
        celery_app.conf.update(task_always_eager=True)

        # Return only lockfiles and vendored files
        filtered_files = [
            PRFile(filename="poetry.lock", status="modified", patch="@@ -1 +1 @@"),
            PRFile(filename="node_modules/pkg/index.js", status="added", patch="@@ -1 +1 @@"),
        ]
        with patch("codepulse.worker.tasks.get_diff_fetcher") as mock_get_fetcher:
            mock_fetcher = MockDiffFetcher(custom_files=filtered_files)
            mock_get_fetcher.return_value = mock_fetcher

            orchestrate_pr_analysis.apply_async(
                kwargs={
                    "installation_id": repo.installation_id,
                    "repository_full_name": repo.full_name,
                    "pull_request_number": run.pull_request_number,
                    "head_sha": run.head_sha,
                    "base_sha": run.base_sha,
                    "pr_author": run.pr_author,
                    "webhook_received_at": datetime.now(timezone.utc).isoformat(),
                    "analysis_run_id": str(run.id),
                }
            )

        db_session.expire_all()
        reloaded = db_session.get(AnalysisRun, run.id)
        assert reloaded is not None
        assert reloaded.status == "skipped"
        assert reloaded.total_findings is None or reloaded.total_findings == 0

        # No findings persisted
        findings = db_session.query(DBFinding).filter(DBFinding.analysis_run_id == run.id).all()
        assert len(findings) == 0
