"""Initial schema — all tables from architecture doc Section 3.7.1.

Revision ID: 001_initial_schema
Revises: -
Create Date: 2026-08-28

Tables created:
  - repositories
  - analysis_runs  (+ unique constraint for idempotency)
  - findings       (+ composite index on analysis_run_id, file_path)
  - llm_usage_log
  - dead_letter_log
  - webhook_events_log
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── repositories ────────────────────────────────────────────────────────
    op.create_table(
        "repositories",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("github_id", sa.BigInteger, unique=True, nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("installation_id", sa.BigInteger, nullable=False),
        sa.Column("default_branch", sa.String(100), nullable=False),
        sa.Column("primary_language", sa.String(50), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_repositories_full_name", "repositories", ["full_name"])
    op.create_index("ix_repositories_installation_id", "repositories", ["installation_id"])

    # ── analysis_runs ───────────────────────────────────────────────────────
    op.create_table(
        "analysis_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "repository_id",
            sa.BigInteger,
            sa.ForeignKey("repositories.id"),
            nullable=False,
        ),
        sa.Column("pull_request_number", sa.Integer, nullable=False),
        sa.Column("head_sha", sa.String(40), nullable=False),
        sa.Column("base_sha", sa.String(40), nullable=False),
        sa.Column("pr_author", sa.String(100), nullable=False),
        sa.Column(
            "status", sa.String(20), nullable=False, server_default="pending"
        ),
        sa.Column("files_analyzed", sa.Integer, nullable=True),
        sa.Column("chunks_total", sa.Integer, nullable=True),
        sa.Column("chunks_completed", sa.Integer, nullable=True),
        sa.Column("total_findings", sa.Integer, nullable=True),
        sa.Column("critical_count", sa.Integer, server_default="0"),
        sa.Column("high_count", sa.Integer, server_default="0"),
        sa.Column("medium_count", sa.Integer, server_default="0"),
        sa.Column("low_count", sa.Integer, server_default="0"),
        sa.Column("analysis_duration_ms", sa.Integer, nullable=True),
        sa.Column("review_posted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("github_review_id", sa.BigInteger, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        # Not in the 3.7.1 table definition but referenced in Section 6.4
        # (graceful degradation). See DECISIONS.md.
        sa.Column(
            "reanalysis_needed",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("webhook_received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'skipped')",
            name="ck_analysis_runs_status",
        ),
    )
    op.create_index("ix_analysis_runs_repository_id", "analysis_runs", ["repository_id"])
    op.create_unique_constraint(
        "uq_analysis_runs_repo_pr_sha",
        "analysis_runs",
        ["repository_id", "pull_request_number", "head_sha"],
    )

    # ── findings ────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "analysis_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id"),
            nullable=False,
        ),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("line_start", sa.Integer, nullable=False),
        sa.Column("line_end", sa.Integer, nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("category", sa.String(20), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("explanation", sa.Text, nullable=False),
        sa.Column("remediation", sa.Text, nullable=False),
        sa.Column("confidence", sa.String(10), nullable=False),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("raw_llm_category", sa.String(50), nullable=True),
        sa.Column(
            "is_posted", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name="ck_findings_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_findings_confidence",
        ),
        sa.CheckConstraint(
            "source IN ('ast', 'llm', 'merged')",
            name="ck_findings_source",
        ),
    )
    op.create_index(
        "ix_findings_analysis_run_file", "findings", ["analysis_run_id", "file_path"]
    )

    # ── llm_usage_log ───────────────────────────────────────────────────────
    op.create_table(
        "llm_usage_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "analysis_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id"),
            nullable=False,
        ),
        sa.Column("model_version", sa.String(50), nullable=False),
        sa.Column("input_tokens", sa.Integer, nullable=False),
        sa.Column("output_tokens", sa.Integer, nullable=False),
        sa.Column("latency_ms", sa.Integer, nullable=False),
        sa.Column(
            "cache_hit", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ── dead_letter_log ─────────────────────────────────────────────────────
    op.create_table(
        "dead_letter_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("task_name", sa.String(100), nullable=False),
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_args", postgresql.JSONB, nullable=False),
        sa.Column("exception_type", sa.String(200), nullable=False),
        sa.Column("exception_message", sa.Text, nullable=False),
        sa.Column("traceback", sa.Text, nullable=False),
        sa.Column("retry_count", sa.Integer, nullable=False),
        sa.Column(
            "resolved", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ── webhook_events_log ──────────────────────────────────────────────────
    op.create_table(
        "webhook_events_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "delivery_id", postgresql.UUID(as_uuid=True), unique=True, nullable=False
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("action", sa.String(50), nullable=True),
        sa.Column("repository_full_name", sa.String(255), nullable=True),
        sa.Column(
            "processed", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "duplicate", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("webhook_events_log")
    op.drop_table("dead_letter_log")
    op.drop_table("llm_usage_log")
    op.drop_table("findings")
    op.drop_table("analysis_runs")
    op.drop_table("repositories")
