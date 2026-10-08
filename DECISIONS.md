# DECISIONS

Design decisions, judgment calls, and architecture-doc inconsistencies
encountered during implementation.

---

## DEC-001: Table partitioning skipped for local development

**Context:** Section 3.7.1 specifies range partitioning on `created_at`:
- `analysis_runs` and `findings`: monthly partitions, 90-day retention.
- `webhook_events_log`: weekly partitions, 30-day retention.

Partitioning requires `pg_partman` and adds operational complexity that is
unnecessary for local Docker-based development and testing.

**Decision:** All tables are created as standard (unpartitioned) tables in the
initial Alembic migration. The schema is otherwise identical. A future migration
will convert to partitioned tables when deploying to a production Kubernetes
environment (Phase 8).

**Impact:** None for correctness or functionality. Retention/archival automation
is deferred.

---

## DEC-002: `reanalysis_needed` column added to `analysis_runs`

**Context:** Section 6.4 (Graceful Degradation) states: *"A `reanalysis_needed`
flag is set on the `analysis_runs` row."* and describes a Celery Beat task that
checks this flag periodically. However, this column is **not listed** in the
`analysis_runs` table definition in Section 3.7.1.

This is an inconsistency in the architecture doc — the behavior requires the
column, but the schema omits it.

**Decision:** Added `reanalysis_needed BOOLEAN NOT NULL DEFAULT FALSE` to the
`analysis_runs` table and ORM model. This is the minimal addition needed to
support the described degradation/re-analysis flow.

---

## DEC-003: `CHAR(40)` → `VARCHAR(40)` for SHA columns

**Context:** The architecture doc specifies `CHAR(40)` for `head_sha` and
`base_sha`. In PostgreSQL, `CHAR(N)` pads values with trailing spaces to the
fixed length, which can cause subtle comparison bugs if values are ever shorter
than 40 characters (unlikely for SHA-1 hex, but defensive coding practice).

**Decision:** Used `VARCHAR(40)` (`sa.String(40)` in SQLAlchemy) instead of
`CHAR(40)`. SHA-1 hex digests are always exactly 40 characters, so this has no
practical impact but avoids the space-padding pitfall. The migration matches the
ORM model.

---

## DEC-004: Poetry chosen over uv for dependency management

**Context:** The project prompt mentioned `uv/poetry` as options.

**Decision:** Poetry was chosen per user confirmation. Poetry provides mature
lock-file management, Docker integration, and broad ecosystem support.

---

## DEC-005: UUID primary keys use application-side `uuid4()` default

**Context:** The architecture doc specifies `DEFAULT gen_random_uuid()` (a
PostgreSQL server-side function) for UUID primary keys on `analysis_runs` and
`findings`.

**Decision:** The Alembic migration uses `server_default=sa.text('gen_random_uuid()')`
to match the doc exactly. The SQLAlchemy ORM model additionally sets
`default=uuid.uuid4` so that UUIDs are assigned on the Python side when
creating objects via the ORM (without requiring a DB round-trip). Both paths
produce valid UUIDv4 values. The server default acts as a safety net for any
raw SQL inserts.

---

## DEC-006: `check_event_listener_leak` matches by event-name string only

**Context:** The JS/TS memory-leak heuristic `check_event_listener_leak`
(Section 3.3.4) scans for `addEventListener` calls and looks for a
corresponding `removeEventListener` call *anywhere in the same file* with the
same event-name string (e.g. `"click"`).

This is a deliberate simplification.  A fully precise check would need to match
on (element, event-name, handler-reference) and track cross-file cleanup (e.g.
the listener is added in one file and removed in a React `useEffect` cleanup in
another).  That level of analysis requires inter-procedural data-flow tracking
that is beyond the scope of lightweight AST heuristics.

**Known limitations:**

- **False negatives:** An unrelated `removeEventListener("click", …)` in the
  same file will suppress a genuine leak on a *different* element or handler.
- **False positives:** Cleanup performed in a different file/chunk (e.g. a
  separate cleanup module) will not be seen, causing a spurious finding.

**Decision:** Accepted as a heuristic tradeoff. The rule provides useful
signal for common SPA patterns (mount without unmount cleanup) where both calls
typically live in the same component file. The LLM analysis path (Phase 4) can
provide deeper cross-file reasoning to compensate.

---

## DEC-007: Slice 3 Refactoring — ASTFinding factory vs cross-language checker unification

**Context:** The initial refactoring plan proposed deduplicating heuristic logic
across Python and JavaScript by introducing shared AST checker abstractions (e.g.
a unified call-expression visitor or cross-language rule checker).

**What the plan promised vs what was delivered:**
- *Plan:* Attempt cross-language checker unification to merge inspection logic.
- *Delivered:* Added `ASTFinding.from_node()` classmethod to `base.py` and converted
  all 21 finding instantiations across `python.py` and `javascript.py`. Cross-language
  checker unification was deliberately skipped.

**Rationale:**
Tree-sitter grammars differ fundamentally between Python and JS/TS:
- Python function calls are `call` nodes with `attribute` children.
- JavaScript function calls are `call_expression` nodes with `member_expression` children.
- Arguments in Python use `argument_list` with keyword arguments (`keyword_argument`),
  whereas JS uses `arguments` with object properties or spread elements.

Creating an artificial abstraction layer across distinct grammar trees introduces
speculative indirection, impairs readability, and increases error risk without
meaningful code reduction. Instead, `ASTFinding.from_node()` targeted the genuine
duplication: repetitive extraction of `file_path`, `line_start`, and `line_end`
from a node's `start_point` and `end_point`. This shrank each call site cleanly
while preserving language-idiomatic AST analysis.

---

## DEC-008: Slice 4 Refactoring — Production MockLLMClient and LLM schema architecture

**Context:** The initial refactoring plan proposed moving `MockLLMClient` out of
production code into `tests/`, merging `LLMAnalysisResult` into other schema
classes, and embedding category remapping into a Pydantic `@model_validator` on
`LLMResponse`.

**What the plan promised vs what was delivered:**
- *Plan:* Move `MockLLMClient` to test directory, merge result classes, and use
  `@model_validator` for category remapping.
- *Delivered:* Retained `MockLLMClient` with full pattern-matching in
  `src/codepulse/analysis/llm_client.py` as production code. Cleaned unused imports
  (`MockLLMClient`, `LLMTokenUsage` in `llm_engine.py`) and normalized PEP 8 import
  ordering. Result class merging and `@model_validator` remapping were skipped.

**Rationale:**
1. **MockLLMClient in production:** The project requires end-to-end operation in
   Docker with `MOCK_LLM=true` without requiring a real Gemini API key or network
   access. Webhook ingestion, Celery worker pipelines, and subsequent integration
   testing (Phase 5+) rely on `get_llm_client(mock_llm=True)` returning realistic,
   pattern-aware findings (OWASP A02, A03, A04, A08, memory leaks). Moving it to
   tests would break containerized development and CI workflows.
2. **Result class separation:** `LLMResponse` represents the raw structured output
   from the Gemini API, whereas `LLMAnalysisResult` represents the outcome of the
   full analysis engine (including status, prompt hash, and post-processed
   findings). Conflating the two would violate single responsibility and mutate API
   transport representations.
3. **Explicit category remapping vs `@model_validator`:** Category remapping is a
   pipeline business logic step (Section 3.4.4), not an input schema validation
   rule. Running it in post-processing preserves the original LLM output for
   auditing (`raw_category`) and allows clean fallback handling without rejecting
   otherwise valid responses.

---

## DEC-009: Slice 6 Refactoring — Test parametrization strategy

**Context:** The initial refactoring plan suggested aggressive test deduplication
and deleting repetitive tests to shrink test file line counts.

**What the plan promised vs what was delivered:**
- *Plan:* Delete duplicate tests to reduce line count.
- *Delivered:* Preserved all test cases and increased total tests from 184 to 192
  via targeted `@pytest.mark.parametrize` tables across:
  - Language detection extension mapping (`test_ast_engine.py`)
  - Table and column verification across all 6 ORM models (`test_models.py`)
  - Check constraint assertions on `Finding` (`test_models.py`)
  - Heuristic fire/silent input-output tables (`test_ast_engine.py`)
  - TypeScript and TSX duplicate evaluations (`test_ast_engine.py`)
  - Category remapping non-standard inputs (`test_llm_engine.py`)
  - Webhook PR event filtering and acceptance actions (`test_webhook.py`)
  Verified test order independence under multiple random seeds using `pytest-randomly`.

**Rationale:**
Readability and regression safety take precedence over minimizing line count.
Parametrizing genuine duplicates into tabular inputs makes expected behavior more
transparent, prevents test suite decay, and maintains high test density without
obscuring failure diagnostics.

---

## DEC-010: Phase 5 Aggregation, Review Posting, and Architecture Stubs

**Context:** Phase 5 integrates findings from AST heuristics (Phase 3) and LLM analysis
(Phase 4) into unified findings, handles deduplication, diff line mapping, and publishes
an atomic PR review to the GitHub Pull Request Review API (§3.5, §3.6).

**Decisions:**
1. **Atomic PR Review API & MockGitHubPoster:**
   - Review comments are posted atomically as a single review via
     `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews` with `event="COMMENT"` (§3.6.1, §3.6.2).
   - A `MockGitHubPoster` is implemented in production code (`src/codepulse/aggregation/github_poster.py`),
     active by default under `MOCK_GITHUB=true`. It strictly validates top-level keys
     (`event`, `body`, `comments`) and comment item keys (`path`, `line`, `side`, `body`)
     and records reviews in memory for deterministic test assertions.
2. **256-Comment Cap Truncation Invariant:**
   - GitHub limits PR reviews to 256 inline comments (§3.6.4).
   - Findings are sorted by severity (`critical` > `high` > `medium` > `low` > `info`),
     then file path, then line number.
   - Truncation strictly enforces the invariant that **no critical finding is ever dropped**
     while lower-severity findings remain in the review. If total findings exceed 256,
     lower-severity findings are omitted and a truncation notice is included in the summary body.
3. **Phase 6 Stubs for Celery Orchestration & Persistence:**
   - *Tier 2 Escalation:* Per §3.4.1, critical findings with low or medium confidence warrant
     re-analysis via `gemini-2.5-pro`. In Phase 5, `check_tier2_escalation()` identifies
     candidates and returns a boolean indicator, with a `TODO (Phase 6)` to spawn an escalation
     subtask on the `cp-analysis` Celery queue before posting.
   - *PostgreSQL Persistence:* Per §3.7.1, findings and analysis run records must be saved
     in PostgreSQL. In Phase 5, `persist_findings_stub()` defines the persistence contract with
     a `TODO (Phase 6)` to execute within the Celery task database session lifecycle.

