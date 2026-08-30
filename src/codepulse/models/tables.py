"""ORM table definitions — mirrors Section 3.7.1 of the architecture doc."""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from codepulse.models.base import Base


class Repository(Base):
    """Tracked GitHub repositories (Section 3.7.1, Table: repositories)."""

    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    github_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    installation_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    default_branch: Mapped[str] = mapped_column(String(100), nullable=False)
    primary_language: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    analysis_runs: Mapped[list["AnalysisRun"]] = relationship(back_populates="repository")


class AnalysisRun(Base):
    """One analysis run per (repo, PR, head_sha) — Section 3.7.1, Table: analysis_runs."""

    __tablename__ = "analysis_runs"
    __table_args__ = (
        UniqueConstraint(
            "repository_id",
            "pull_request_number",
            "head_sha",
            name="uq_analysis_runs_repo_pr_sha",
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'skipped')",
            name="ck_analysis_runs_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    repository_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("repositories.id"), nullable=False, index=True
    )
    pull_request_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    base_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    pr_author: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    files_analyzed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    chunks_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    chunks_completed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_findings: Mapped[int | None] = mapped_column(Integer, nullable=True)
    critical_count: Mapped[int] = mapped_column(Integer, server_default="0")
    high_count: Mapped[int] = mapped_column(Integer, server_default="0")
    medium_count: Mapped[int] = mapped_column(Integer, server_default="0")
    low_count: Mapped[int] = mapped_column(Integer, server_default="0")
    analysis_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    review_posted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    github_review_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Added per Section 6.4 — not in original table def but referenced in graceful degradation.
    # Logged in DECISIONS.md.
    reanalysis_needed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    webhook_received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    repository: Mapped["Repository"] = relationship(back_populates="analysis_runs")
    findings: Mapped[list["Finding"]] = relationship(back_populates="analysis_run")
    llm_usage_logs: Mapped[list["LlmUsageLog"]] = relationship(back_populates="analysis_run")


class Finding(Base):
    """Individual vulnerability/memory-leak finding — Section 3.7.1, Table: findings."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_analysis_run_file", "analysis_run_id", "file_path"),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name="ck_findings_severity",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_findings_confidence",
        ),
        CheckConstraint(
            "source IN ('ast', 'llm', 'merged')",
            name="ck_findings_source",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analysis_runs.id"), nullable=False
    )
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    category: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False)
    source: Mapped[str] = mapped_column(String(10), nullable=False)
    raw_llm_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_posted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    analysis_run: Mapped["AnalysisRun"] = relationship(back_populates="findings")


class LlmUsageLog(Base):
    """Token usage and latency per LLM API call — Section 3.7.1, Table: llm_usage_log."""

    __tablename__ = "llm_usage_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analysis_runs.id"), nullable=False
    )
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    cache_hit: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    analysis_run: Mapped["AnalysisRun"] = relationship(back_populates="llm_usage_logs")


class DeadLetterLog(Base):
    """Failed tasks after max retries — Section 3.7.1, Table: dead_letter_log."""

    __tablename__ = "dead_letter_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    task_name: Mapped[str] = mapped_column(String(100), nullable=False)
    task_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    task_args: Mapped[dict] = mapped_column(JSONB, nullable=False)  # type: ignore[assignment]
    exception_type: Mapped[str] = mapped_column(String(200), nullable=False)
    exception_message: Mapped[str] = mapped_column(Text, nullable=False)
    traceback: Mapped[str] = mapped_column(Text, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class WebhookEventLog(Base):
    """Operational log of every received webhook — Section 3.7.1, Table: webhook_events_log."""

    __tablename__ = "webhook_events_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    delivery_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    action: Mapped[str | None] = mapped_column(String(50), nullable=True)
    repository_full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    processed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    duplicate: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
