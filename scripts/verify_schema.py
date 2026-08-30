#!/usr/bin/env python3
"""Verify that all CodePulse AI tables exist in PostgreSQL after migration.

Usage (run against the docker-compose Postgres):
    python scripts/verify_schema.py

Exits with code 0 if all tables and key constraints are present.
"""

import sys

from sqlalchemy import create_engine, inspect, text

DATABASE_URL = "postgresql://codepulse:codepulse_dev@localhost:5432/codepulse"

EXPECTED_TABLES = [
    "repositories",
    "analysis_runs",
    "findings",
    "llm_usage_log",
    "dead_letter_log",
    "webhook_events_log",
]

# Columns per table (from architecture doc Section 3.7.1)
EXPECTED_COLUMNS = {
    "repositories": [
        "id", "github_id", "full_name", "installation_id",
        "default_branch", "primary_language", "created_at", "updated_at",
    ],
    "analysis_runs": [
        "id", "repository_id", "pull_request_number", "head_sha", "base_sha",
        "pr_author", "status", "files_analyzed", "chunks_total",
        "chunks_completed", "total_findings", "critical_count", "high_count",
        "medium_count", "low_count", "analysis_duration_ms", "review_posted_at",
        "github_review_id", "error_message", "reanalysis_needed",
        "webhook_received_at", "created_at",
    ],
    "findings": [
        "id", "analysis_run_id", "file_path", "line_start", "line_end",
        "severity", "category", "title", "explanation", "remediation",
        "confidence", "source", "raw_llm_category", "is_posted", "created_at",
    ],
    "llm_usage_log": [
        "id", "analysis_run_id", "model_version", "input_tokens",
        "output_tokens", "latency_ms", "cache_hit", "created_at",
    ],
    "dead_letter_log": [
        "id", "task_name", "task_id", "task_args", "exception_type",
        "exception_message", "traceback", "retry_count", "resolved",
        "created_at",
    ],
    "webhook_events_log": [
        "id", "delivery_id", "event_type", "action",
        "repository_full_name", "processed", "duplicate", "received_at",
    ],
}


def main() -> int:
    print(f"Connecting to: {DATABASE_URL}")
    engine = create_engine(DATABASE_URL)
    inspector = inspect(engine)

    errors: list[str] = []

    # Check tables exist
    existing_tables = inspector.get_table_names()
    print(f"\nExisting tables: {existing_tables}")

    for table in EXPECTED_TABLES:
        if table not in existing_tables:
            errors.append(f"MISSING TABLE: {table}")
            continue

        print(f"\n✅ Table '{table}' exists")

        # Check columns
        actual_cols = {col["name"] for col in inspector.get_columns(table)}
        expected_cols = set(EXPECTED_COLUMNS[table])
        missing = expected_cols - actual_cols
        extra = actual_cols - expected_cols

        if missing:
            errors.append(f"  Table '{table}' missing columns: {missing}")
        if extra:
            print(f"  ⚠️  Extra columns (not necessarily wrong): {extra}")

        for col_name in sorted(expected_cols & actual_cols):
            print(f"    - {col_name}")

    # Check the idempotency unique constraint on analysis_runs
    if "analysis_runs" in existing_tables:
        uqs = inspector.get_unique_constraints("analysis_runs")
        uq_names = [u["name"] for u in uqs]
        if "uq_analysis_runs_repo_pr_sha" not in uq_names:
            errors.append("MISSING unique constraint: uq_analysis_runs_repo_pr_sha")
        else:
            print("\n✅ Idempotency unique constraint 'uq_analysis_runs_repo_pr_sha' exists")

    # Check check constraints on findings
    if "findings" in existing_tables:
        with engine.connect() as conn:
            result = conn.execute(text(
                "SELECT conname FROM pg_constraint "
                "WHERE conrelid = 'findings'::regclass AND contype = 'c'"
            ))
            check_names = {row[0] for row in result}

        for expected_ck in ["ck_findings_severity", "ck_findings_confidence", "ck_findings_source"]:
            if expected_ck in check_names:
                print(f"✅ Check constraint '{expected_ck}' exists")
            else:
                errors.append(f"MISSING check constraint: {expected_ck}")

    # Summary
    print("\n" + "=" * 60)
    if errors:
        print("❌ VERIFICATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    else:
        print("✅ ALL CHECKS PASSED — schema is correct.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
