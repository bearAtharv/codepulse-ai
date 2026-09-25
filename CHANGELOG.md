# CHANGELOG

All notable changes to CodePulse AI are documented here.

## [Unreleased] — Phase 4: LLM Analysis Engine (Gemini)

### Added
- **LLM analysis engine** (`src/codepulse/analysis/llm_engine.py`) — main entry
  point `analyze_llm(chunks, repo_name, language)` that constructs a structured
  prompt, calls the Gemini API (or mock), validates the response, remaps OWASP
  categories, and returns structured findings (Section 3.4).
- **Prompt construction** (`src/codepulse/analysis/llm_prompt.py`) — builds the
  four-section prompt per §3.4.2: system instruction, repository context,
  CODE_DIFF-wrapped chunks (§3.4.7 prompt injection defense), and analysis
  directives. SHA-256 prompt hashing for cache keying (§3.4.5).
- **Pydantic response schemas** (`src/codepulse/analysis/llm_schemas.py`) —
  `LLMResponse`, `LLMFindingItem`, `LLMTokenUsage`, `LLMResponseMetadata`
  matching the structured output schema from §3.4.3. OWASP category remapping
  with keyword lookup (§3.4.4) and `raw_category` preservation for auditing.
- **LLM client abstraction** (`src/codepulse/analysis/llm_client.py`):
  - `GeminiClient` — real API client using `google-genai` SDK with structured
    output mode, no function declarations (§3.4.7), and system instruction
    isolation.
  - `MockLLMClient` — pattern-aware mock that detects SQL injection, eval/exec,
    hardcoded secrets, weak hashing, deserialization, empty exceptions, and
    memory leaks in prompt content, returning realistic canned responses with
    non-standard categories to exercise remapping.
  - Factory `get_llm_client()` selects based on `MOCK_LLM` config flag.
- **Prompt injection defenses** implemented per §3.4.7:
  - Input/instruction separation (system instruction set once at client init)
  - Output schema enforcement (structured output mode)
  - CODE_DIFF delimiter wrapping with explicit untrusted-content warning
  - Output validation (findings referencing files not in the prompt are discarded)
  - No tool use (no function declarations configured)
- **Error handling** — retry-once on schema validation failure (§3.4.3 /
  Branch E), then fallback to `analysis_status=llm_error` with AST-only results.
- **`google-genai`** SDK added to `pyproject.toml`.
- **Tests** — 54 new tests in `tests/test_llm_engine.py`:
  - 2 system instruction tests (key phrases, fixed string)
  - 8 prompt construction tests (4 sections, CODE_DIFF wrapping, multi-chunk)
  - 3 prompt hash tests (determinism, content-sensitivity, hex format)
  - 9 OWASP category remapping tests (passthrough, remap, raw preservation)
  - 7 response schema parsing tests (valid, empty, extra fields, missing/invalid)
  - 11 mock client tests (multi-category detection, clean silence, token usage)
  - 2 client factory tests (mock mode, missing key error)
  - 2 output validation tests (§3.4.7 file path filtering)
  - 3 error handling tests (retry-once, persistent failure, empty chunks)
  - 2 category remapping integration tests (end-to-end remap + raw_category)
  - 5 end-to-end integration tests (vulnerable/clean code, finding structure, hash stability)

## [Unreleased] — Phase 3: AST Analysis Engine (Python + JS/TS)

### Added
- **AST analysis engine** (`src/codepulse/analysis/ast_engine.py`) — main entry
  point `analyze_chunk(source, filename, modified_lines=…)` that parses code
  via tree-sitter, runs all applicable heuristics, and returns structured
  `ASTFinding` objects (Section 3.3).
- **Language registry** (`src/codepulse/analysis/languages.py`) — maps file
  extensions to tree-sitter grammars.  Supported: Python (`.py`, `.pyi`),
  JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`), TypeScript (`.ts`), TSX (`.tsx`).
- **Python OWASP heuristics** (11 rules):
  - A03: SQL injection (string concat + f-string), eval/exec, command injection
    (subprocess/os.system)
  - A04: Empty except blocks (bare or broad catch with only `pass`)
  - A02: Hardcoded secrets, weak crypto (hashlib.md5/sha1)
  - A05: `DEBUG = True`, binding to `0.0.0.0`
  - A08: Dangerous deserialization (pickle.loads, yaml.load without SafeLoader)
  - A09: Sensitive data in logging/print calls
  - A07: JWT decode with `verify=False`
  - A10: SSRF (user-controlled URL in requests.get, httpx, urllib)
- **Python memory-leak heuristic** — `open()` without `with` statement
  (Section 3.3.4).
- **JS/TS OWASP heuristics** (6 rules):
  - A03: eval(), SQL injection (string concat + template literal), innerHTML XSS
  - A04: Empty catch blocks
  - A02: Hardcoded secrets in const/let/var declarations
  - A09: Sensitive data in console.log/warn/error
- **JS/TS memory-leak heuristic** — `addEventListener` without corresponding
  `removeEventListener` in the same file (Section 3.3.4).
- **Diff-aware filtering** (Section 3.3.2) — optional `modified_lines` parameter
  restricts findings to only lines that were actually changed in the diff.
- **tree-sitter dependencies** added to `pyproject.toml`: `tree-sitter`,
  `tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-typescript`.
- **Test fixtures** — known-vulnerable and known-clean code files for Python
  and JavaScript in `tests/fixtures/`.
- **Tests** — 69 new tests in `tests/test_ast_engine.py`:
  - 5 language detection tests
  - 38 Python heuristic tests (fire on vulnerable + silent on clean per rule)
  - 16 JS/TS heuristic tests (fire on vulnerable + silent on clean per rule)
  - 3 TypeScript-specific tests (TS/TSX get same JS heuristics)
  - 3 diff-aware filtering tests
  - 2 finding structure validation tests
  - 2 integration tests (full fixture files — vulnerable and clean)
- **DECISIONS.md** — DEC-006: documents `check_event_listener_leak`
  event-name-only matching limitation.

## [Unreleased] — Phase 2: Webhook Ingestion Service

### Added
- **FastAPI webhook endpoint** (`POST /webhooks`) implementing the full
  Section 3.1 flow:
  - HMAC-SHA256 signature verification with constant-time comparison
    (Section 3.1.1).
  - Event filtering: accepts `pull_request` with actions `opened`,
    `synchronize`, `reopened`; responds to `ping` with `{"status": "pong"}`;
    silently discards all other events (Section 3.1.2).
  - Redis-based idempotency via `SET NX` with 1-hour TTL on key
    `idempotency:{installation_id}:{pr}:{sha}` (Section 3.1.3).
  - DB-level idempotency fallback via `ON CONFLICT DO NOTHING` on the
    `(repository_id, pull_request_number, head_sha)` unique constraint
    (Section 6.1, Level 2).
  - Repository upsert (`INSERT ... ON CONFLICT DO UPDATE`) and
    `analysis_runs` row creation with `status='pending'` (Section 10.1, Step 5).
  - Celery task enqueue to `cp-high` queue (Section 3.1.4).
  - Webhook event logging to `webhook_events_log` with processed/duplicate
    flags.
- **Health endpoints** (`/health/live`, `/health/ready`) checking Redis and
  PostgreSQL connectivity (Section 8.5).
- **Celery worker stub** (`src/codepulse/worker/`) — app configuration and
  `tasks.orchestrate_pr_analysis` task stub that logs receipt. Actual pipeline
  wiring deferred to Phase 6.
- **Database caching** — `persistence/database.py` now caches SQLAlchemy
  engines and session factories per-URL.
- **docker-compose `web` service** — runs uvicorn on port 8000, depends on
  migrations completing first.
- **Tests** — 28 new tests in `tests/test_webhook.py`:
  - 7 signature verification tests (including constant-time check)
  - 3 HTTP-level signature tests (valid/bad/missing)
  - 7 event filtering tests (ping, opened/sync/reopened, closed/labeled/unknown)
  - 5 idempotency tests (first/dup/different-SHA/task-not-enqueued/DB-fallback)
  - 2 task enqueue tests (kwargs correctness, service function calls)
  - 3 webhook logging tests (processed/filtered/duplicate flags)
  - 1 health endpoint test

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
