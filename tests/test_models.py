"""Tests for SQLAlchemy ORM model definitions.

These tests verify the model metadata (table names, columns, constraints,
indexes) WITHOUT requiring a live database connection.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import inspect as sa_inspect

from codepulse.models import (
    AnalysisRun,
    Base,
    DeadLetterLog,
    Finding,
    LlmUsageLog,
    Repository,
    WebhookEventLog,
)


# ── Table existence ─────────────────────────────────────────────────────────


class TestTableRegistration:
    """All 6 tables from Section 3.7.1 must be registered on Base.metadata."""

    EXPECTED_TABLES = {
        "repositories",
        "analysis_runs",
        "findings",
        "llm_usage_log",
        "dead_letter_log",
        "webhook_events_log",
    }

    def test_all_tables_registered(self) -> None:
        registered = set(Base.metadata.tables.keys())
        assert self.EXPECTED_TABLES.issubset(registered), (
            f"Missing tables: {self.EXPECTED_TABLES - registered}"
        )

    def test_no_unexpected_tables(self) -> None:
        registered = set(Base.metadata.tables.keys())
        assert registered == self.EXPECTED_TABLES, (
            f"Unexpected extra tables: {registered - self.EXPECTED_TABLES}"
        )


# ── Column verification ────────────────────────────────────────────────────


class TestRepositoryModel:
    def test_tablename(self) -> None:
        assert Repository.__tablename__ == "repositories"

    def test_columns(self) -> None:
        cols = {c.name for c in Repository.__table__.columns}
        expected = {
            "id", "github_id", "full_name", "installation_id",
            "default_branch", "primary_language", "created_at", "updated_at",
        }
        assert cols == expected

    def test_github_id_unique(self) -> None:
        col = Repository.__table__.c.github_id
        assert col.unique is True

    def test_full_name_indexed(self) -> None:
        indexes = {idx.name for idx in Repository.__table__.indexes}
        assert any("full_name" in idx for idx in indexes)


class TestAnalysisRunModel:
    def test_tablename(self) -> None:
        assert AnalysisRun.__tablename__ == "analysis_runs"

    def test_columns(self) -> None:
        cols = {c.name for c in AnalysisRun.__table__.columns}
        expected = {
            "id", "repository_id", "pull_request_number", "head_sha",
            "base_sha", "pr_author", "status", "files_analyzed",
            "chunks_total", "chunks_completed", "total_findings",
            "critical_count", "high_count", "medium_count", "low_count",
            "analysis_duration_ms", "review_posted_at", "github_review_id",
            "error_message", "reanalysis_needed", "webhook_received_at",
            "created_at",
        }
        assert cols == expected

    def test_idempotency_unique_constraint(self) -> None:
        """The (repository_id, pull_request_number, head_sha) tuple must be unique."""
        constraints = AnalysisRun.__table__.constraints
        uq = [c for c in constraints if hasattr(c, "columns") and len(getattr(c, "columns", [])) == 3]
        uq_col_sets = [
            {col.name for col in c.columns}
            for c in constraints
            if c.__class__.__name__ == "UniqueConstraint"
        ]
        assert {"repository_id", "pull_request_number", "head_sha"} in uq_col_sets

    def test_status_check_constraint(self) -> None:
        """Status must be one of: pending, running, completed, failed, skipped."""
        check_names = [
            c.name for c in AnalysisRun.__table__.constraints
            if c.__class__.__name__ == "CheckConstraint"
        ]
        assert "ck_analysis_runs_status" in check_names

    def test_repository_fk(self) -> None:
        col = AnalysisRun.__table__.c.repository_id
        fks = list(col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].target_fullname == "repositories.id"


class TestFindingModel:
    def test_tablename(self) -> None:
        assert Finding.__tablename__ == "findings"

    def test_columns(self) -> None:
        cols = {c.name for c in Finding.__table__.columns}
        expected = {
            "id", "analysis_run_id", "file_path", "line_start", "line_end",
            "severity", "category", "title", "explanation", "remediation",
            "confidence", "source", "raw_llm_category", "is_posted",
            "created_at",
        }
        assert cols == expected

    def test_severity_check(self) -> None:
        check_names = [
            c.name for c in Finding.__table__.constraints
            if c.__class__.__name__ == "CheckConstraint"
        ]
        assert "ck_findings_severity" in check_names

    def test_confidence_check(self) -> None:
        check_names = [
            c.name for c in Finding.__table__.constraints
            if c.__class__.__name__ == "CheckConstraint"
        ]
        assert "ck_findings_confidence" in check_names

    def test_source_check(self) -> None:
        check_names = [
            c.name for c in Finding.__table__.constraints
            if c.__class__.__name__ == "CheckConstraint"
        ]
        assert "ck_findings_source" in check_names

    def test_composite_index(self) -> None:
        indexes = {idx.name for idx in Finding.__table__.indexes}
        assert "ix_findings_analysis_run_file" in indexes

    def test_analysis_run_fk(self) -> None:
        col = Finding.__table__.c.analysis_run_id
        fks = list(col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].target_fullname == "analysis_runs.id"


class TestLlmUsageLogModel:
    def test_tablename(self) -> None:
        assert LlmUsageLog.__tablename__ == "llm_usage_log"

    def test_columns(self) -> None:
        cols = {c.name for c in LlmUsageLog.__table__.columns}
        expected = {
            "id", "analysis_run_id", "model_version", "input_tokens",
            "output_tokens", "latency_ms", "cache_hit", "created_at",
        }
        assert cols == expected


class TestDeadLetterLogModel:
    def test_tablename(self) -> None:
        assert DeadLetterLog.__tablename__ == "dead_letter_log"

    def test_columns(self) -> None:
        cols = {c.name for c in DeadLetterLog.__table__.columns}
        expected = {
            "id", "task_name", "task_id", "task_args", "exception_type",
            "exception_message", "traceback", "retry_count", "resolved",
            "created_at",
        }
        assert cols == expected

    def test_task_args_is_jsonb(self) -> None:
        col = DeadLetterLog.__table__.c.task_args
        assert col.type.__class__.__name__ == "JSONB"


class TestWebhookEventLogModel:
    def test_tablename(self) -> None:
        assert WebhookEventLog.__tablename__ == "webhook_events_log"

    def test_columns(self) -> None:
        cols = {c.name for c in WebhookEventLog.__table__.columns}
        expected = {
            "id", "delivery_id", "event_type", "action",
            "repository_full_name", "processed", "duplicate", "received_at",
        }
        assert cols == expected

    def test_delivery_id_unique(self) -> None:
        col = WebhookEventLog.__table__.c.delivery_id
        assert col.unique is True


# ── ORM instantiation (no DB needed) ───────────────────────────────────────


class TestModelInstantiation:
    """Verify that ORM objects can be created in-memory with valid data."""

    def test_create_repository(self) -> None:
        repo = Repository(
            github_id=12345,
            full_name="owner/repo",
            installation_id=67890,
            default_branch="main",
        )
        assert repo.full_name == "owner/repo"
        assert repo.primary_language is None

    def test_create_analysis_run(self) -> None:
        run = AnalysisRun(
            repository_id=1,
            pull_request_number=42,
            head_sha="a" * 40,
            base_sha="b" * 40,
            pr_author="developer",
            webhook_received_at=datetime.now(timezone.utc),
        )
        assert run.status is None  # server_default only applies on INSERT
        assert run.reanalysis_needed is None

    def test_create_finding(self) -> None:
        finding = Finding(
            analysis_run_id=uuid.uuid4(),
            file_path="src/app.py",
            line_start=10,
            line_end=15,
            severity="high",
            category="A03",
            title="SQL Injection",
            explanation="User input concatenated into SQL query",
            remediation="Use parameterized queries",
            confidence="high",
            source="ast",
        )
        assert finding.title == "SQL Injection"
        assert finding.raw_llm_category is None

    def test_create_dead_letter(self) -> None:
        dl = DeadLetterLog(
            task_name="tasks.post_review",
            task_id=uuid.uuid4(),
            task_args={"repo": "owner/repo", "pr": 1},
            exception_type="ConnectionError",
            exception_message="GitHub API unreachable",
            traceback="Traceback (most recent call last):\n...",
            retry_count=5,
        )
        assert dl.task_args["repo"] == "owner/repo"
