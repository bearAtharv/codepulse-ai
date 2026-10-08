# CHANGELOG

All notable changes to CodePulse AI are documented here.

## [Unreleased] — Phase 5: Finding Aggregation, Deduplication, and GitHub Review Posting

### Added
- **Pipeline orchestrator** (`src/codepulse/aggregation/engine.py`):
  - `aggregate_and_post()` entry point coordinating finding normalization, deduplication, diff line mapping, markdown formatting, and atomic review delivery.
  - Stubs for Tier 2 escalation (`check_tier2_escalation()` per §3.4.1) and persistence (`persist_findings_stub()` per §3.7.1), with Celery integration deferred to Phase 6 and documented in DEC-010.
- **Unified Finding models & adapters** (`src/codepulse/aggregation/models.py`):
  - `Finding` dataclass standardizing fields across AST and LLM engines.
  - `Finding.from_ast_finding()` and `Finding.from_llm_finding()` adapter methods.
  - `RepoContext` holding PR metadata, runtime duration, and model version.
  - `DeduplicationResult` and `AggregationResult` containers.
- **Deduplication and collision resolution** (`src/codepulse/aggregation/dedup.py`):
  - Deduplicates on `(file_path, line_start, category, title)`.
  - Confidence-weighted merging: higher confidence finding wins; lower-confidence source is attributed (`"Also detected by {source}."`); source marked as `"merged"`.
  - Severity sorting (`critical` > `high` > `medium` > `low` > `info`), followed by file path and line number.
  - Truncation to GitHub's 256-comment review limit with strict invariant: **critical findings are never dropped** while non-critical findings remain.
- **Diff parsing and line position mapping** (`src/codepulse/aggregation/line_mapping.py`):
  - `parse_unified_diff()` extracts per-file hunk headers, modified lines (`+`), and context lines (` `).
  - Multi-line findings placed on `line_end` with `start_line` set.
  - Context-only findings remapped to nearest modified line in the hunk with an explanatory footnote.
  - Findings outside all hunks or in unchanged files marked `is_in_diff=False`.
- **Review comment and summary formatting** (`src/codepulse/aggregation/comments.py`, `src/codepulse/aggregation/summary.py`):
  - Inline comments with severity emoji badges (🔴, 🟠, 🟡, 🔵, ℹ️), OWASP category code, explanation, and markdown `suggestion` blocks for remediation.
  - Top-level review body with badge overview, analysis metrics table, truncation notices, unmapped findings section, and collapsible `<details>` methodology disclosure.
- **GitHub Review API client and mock mode** (`src/codepulse/aggregation/github_poster.py`):
  - `GitHubReviewPayload` and `ReviewCommentPayload` Pydantic models for `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews` with `event="COMMENT"` (§3.6.1, §3.6.2).
  - `MockGitHubPoster` verifying payload keys (`event`, `body`, `comments[].path/line/side/body`) and recording reviews in memory under `MOCK_GITHUB=true`.
  - `GitHubPoster` production client using `httpx` with GitHub App bearer token authentication.
  - Factory `get_github_poster()` reading `mock_github` configuration.
- **Tests** — 33 new unit tests in `tests/test_aggregation.py`:
  - 2 model adapter tests (AST and LLM).
  - 3 deduplication and collision merging tests (confidence precedence, explanation attribution).
  - 1 multi-level sorting test (severity, file, line).
  - 2 truncation cap invariant tests (ensuring 0 critical findings dropped under 256 cap and custom caps).
  - 6 diff parsing and line mapping tests (added lines, multi-line ranges, context remapping, out-of-hunk).
  - 2 comment formatting tests (suggestion block, remediation fallback, metadata footer).
  - 3 review summary composition tests (overview table, truncation alert, clean PR).
  - 7 mock poster tests (payload key validation, rejection of missing event/body/comments/path/line/side/body, factory).
  - 5 Tier 2 escalation & persistence stub tests.
  - 1 end-to-end `aggregate_and_post()` test with mock poster payload inspection.

## [Unreleased] — Codebase Refactor & Bug Fixes (Slices 1–6)

### Fixed
- **Readiness probe HTTP 503** (`src/codepulse/ingestion/app.py`): `/health/ready`
  now correctly returns HTTP 503 (was 200) when Redis or PostgreSQL is unreachable.
- **Event loop unblocking**: `readiness()` changed from `async def` to sync `def`
  so synchronous database and Redis pings execute in FastAPI threadpool.
- **Configuration caching**: `get_settings()` now cached via `@lru_cache(maxsize=1)`
  in `src/codepulse/config.py` with an autouse cache-clearer fixture in `tests/conftest.py`.
- **Datetime round-trip eliminated**: `src/codepulse/ingestion/webhook.py` passes
  datetime objects directly to `create_analysis_run()`, serializing to ISO 8601 only
  for Celery kwargs.

### Changed / Refactored
- **Module consolidation (Slice 1)**:
  - Inlined `models/base.py` into `models/tables.py`.
  - Inlined `ingestion/signature.py` into `ingestion/webhook.py`.
  - Moved session/redis dependency providers from `ingestion/dependencies.py` to
    `persistence/database.py`.
  - Merged `python_memory.py` into `heuristics/python.py` and `javascript_memory.py`
    into `heuristics/javascript.py`.
  - Merged prompt builder from `analysis/llm_prompt.py` into `analysis/llm_engine.py`.
- **Dead code removal (Slice 2)**: Removed unused `GEMINI_RESPONSE_SCHEMA`,
  `SUPPORTED_LANGUAGES`, unused `source: bytes` parameters from heuristics, and dead imports.
- **Deduplication (Slice 3)**: Added `ASTFinding.from_node()` factory method to `base.py`
  and refactored all 21 finding instantiations across Python and JavaScript heuristics.
- **LLM engine consolidation (Slice 4)**: Cleaned unused imports in `llm_engine.py` while
  retaining full pattern-matching `MockLLMClient` in production `llm_client.py`.
- **Test parameterization (Slice 6)**: Parameterized model metadata tests, language
  detection, webhook event actions, category remapping, TS/TSX evaluations, and
  heuristic fire/silent pairs. Total test count increased from 181 to 192 (0 failures).

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
