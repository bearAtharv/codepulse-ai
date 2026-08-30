# CHANGELOG

All notable changes to CodePulse AI are documented here.
## [Unreleased] — Phase 1: Project Skeleton + Data Model

### Added
- **Project structure:** Python package under `src/codepulse/` with sub-packages
  for each architectural component (`ingestion`, `worker`, `analysis`,
  `aggregation`, `persistence`, `common`, `models`).
- **Dependency management:** Poetry (`pyproject.toml`) with Python 3.12, FastAPI,
  Celery, SQLAlchemy, Alembic, Redis, Pydantic, and dev tooling (pytest, ruff,
  mypy).
- **Docker Compose:** Postgres 16 + Redis 7.2 for local development, plus a
  `migrate` service that runs Alembic migrations on startup.
- **Dockerfile:** Multi-purpose image (migration runner, future web/worker
  services).
- **Alembic migrations:** Initial migration (`001_initial_schema`) creating all 6
  tables from architecture doc Section 3.7.1:
  - `repositories` — tracked GitHub repositories
  - `analysis_runs` — one row per (repo, PR, head_sha) with idempotency
    unique constraint
  - `findings` — individual vulnerability / memory-leak findings with check
    constraints on severity, confidence, source
  - `llm_usage_log` — token usage tracking per LLM API call
  - `dead_letter_log` — failed tasks with full exception context (JSONB args)
  - `webhook_events_log` — operational log of every received webhook
- **SQLAlchemy ORM models:** Full model definitions in `src/codepulse/models/`
  mirroring the migration, with relationships between Repository → AnalysisRun →
  Finding and LlmUsageLog.
- **Configuration:** Pydantic `BaseSettings` in `src/codepulse/config.py`
  reading all connection strings, secrets, TTLs, and mock-mode flags from
  environment variables.
- **Tests:** `tests/test_models.py` — verifies all models load correctly and
  have the expected columns and constraints (runs without a database).
- **Verification script:** `scripts/verify_schema.py` — connects to Postgres
  via docker-compose and asserts all 6 tables exist with correct columns.
- **DECISIONS.md:** Documents design decisions and architecture doc
  inconsistencies found during implementation.

### Stubbed / Deferred
- **Table partitioning** (Section 3.7.1): `analysis_runs` and `findings`
  should be range-partitioned by `created_at` monthly; `webhook_events_log`
  weekly. Skipped for local dev — tables are unpartitioned. See DECISIONS.md.
- **FastAPI application:** Package exists but no routes yet (Phase 2).
- **Celery configuration:** Package exists but no tasks yet (Phase 6).
- **AST / LLM analysis engines:** Packages exist but empty (Phases 3-4).
- **Aggregation / review posting:** Package exists but empty (Phase 5).
