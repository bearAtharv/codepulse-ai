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
   - Findings are sorted by severity (`critical` > `high` > `medium` > `low`),
     then file path, then line number.
   - Truncation strictly enforces the invariant that **no critical finding is ever dropped**
     while lower-severity findings remain in the review. If total findings exceed 256,
     lower-severity findings are omitted and a truncation notice is included in the summary body.
3. **Severity Alignment with Database & Architecture Constraints:**
   - The `findings` table strictly enforces `ck_findings_severity`: `severity IN ('critical', 'high', 'medium', 'low')`.
   - The LLM response schema `Severity` enum and architecture doc §3.4.3 / §3.7.1 also define exactly those 4 severities.
   - Defensive references to `info` severity were removed from Phase 5 (`SEVERITY_ORDER`, badges, summaries) to prevent any mismatch where unhandled `info` findings would be rejected by Postgres with an `IntegrityError` during persistence.
4. **Phase 6 Stubs for Celery Orchestration & Persistence:**
   - *Tier 2 Escalation:* Per §3.4.1, critical findings with low or medium confidence warrant
     re-analysis via `gemini-2.5-pro`. In Phase 5, `check_tier2_escalation()` identifies
     candidates and returns a boolean indicator, with a `TODO (Phase 6)` to spawn an escalation
     subtask on the `cp-analysis` Celery queue before posting.
   - *PostgreSQL Persistence:* Per §3.7.1, findings and analysis run records must be saved
     in PostgreSQL. In Phase 5, `persist_findings_stub()` defines the persistence contract with
     a `TODO (Phase 6)` to execute within the Celery task database session lifecycle.
5. **Components Unverified Without Real External Credentials:**
   The following components operate against mock implementations or stubs and remain unverified against live third-party APIs until production credentials are provided:
   - **`GitHubPoster` against real GitHub API:** `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews` requires a live GitHub App installation token or personal access token to verify GitHub's actual HTTP response formatting, rate limiting (403/5xx), and permission boundaries.
   - **GitHub App Installation-Token Exchange:** Authenticating as a GitHub App via RS256 JWT exchange (`POST /app/installations/{installation_id}/access_tokens` per §3.1.2) requires a valid private key PEM file (`GITHUB_APP_PRIVATE_KEY_PATH`) and App ID.
   - **`GeminiClient` against real Gemini API:** Live inference with `gemini-3.7-flash` requires a valid `GEMINI_API_KEY` to verify upstream latency, network timeouts, real token quotas, and live structured output compliance under actual API conditions.

---

## DEC-011: Cross-source finding deduplication on (file_path, line_start, category, vulnerability family)

**Context:** Section 3.6.4 (Batching and Deduplication) states:
> *"Before posting, findings are deduplicated on `(file_path, line_start, category, title)`. If AST and LLM both flag the same line with the same category, the finding with higher confidence is kept, and the other's explanation is appended as 'Also detected by {source}'."*

There is an inherent conflict between these two sentences:
1. The literal deduplication key is specified as a 4-field tuple: `(file_path, line_start, category, title)`.
2. However, AST heuristics and LLM prompts will almost never generate the exact same `title` string for an issue (e.g., AST produces `"Use of eval() is a code-injection risk"` while LLM produces `"Code injection via eval/exec"`).
3. Conversely, relaxing matching solely to `(file_path, line_start, category)` causes unrelated vulnerabilities on the same line sharing an OWASP category (e.g. `eval()` and SQL injection both under `A03`) to improperly collide and merge, downgrading critical issues and leaving duplicate comments for surviving findings.

**Decision (Judgment Call):**
1. **Deduplication Rules:**
   - **Same-Source Deduplication:** Retain the strict 4-field key `(file_path, line_start, category, title)` for findings originating from the same engine (e.g., two AST findings or two LLM findings).
   - **Cross-Source Merging:** An AST finding and an LLM finding are paired and merged if and only if they share `file_path`, `line_start`, `category`, and a common **vulnerability family**.
   - **Vulnerability Family Classifier:** A coarse-grained family classifier (`get_vulnerability_family()`) derives the issue type (`sql`, `eval`, `command`, `xss`, `secret`, `crypto`, `deserialization`, `memory_leak`, `empty_except`, `sensitive_log`, `ssrf`, `jwt`, `debug`, `bind`) by inspecting the AST `rule_id` and the finding's `title` and `explanation` keywords.
   - **Single Counterpart Invariant:** A finding may merge with at most one counterpart. Once merged, its source is marked `"merged"`, preventing further merges.
   - **Severity & Confidence Union:** A merged finding's severity is strictly the **higher** of the two severities (never downgraded), and its confidence is strictly the **higher** of the two confidences.
   - **Attribution:** The higher-confidence finding (or higher-severity if tied) provides the primary title and explanation text, with `"Also detected by {loser_source}."` appended.

**Known Limitations:**
- **Keyword & Rule Heuristic:** If an LLM writes an explanation using novel terminology that does not match known family keywords, it falls back to matching on canonical category code.
- **Multiple Vulnerabilities of Same Family on One Line:** If two distinct vulnerabilities of the same family exist on the exact same line (e.g., two distinct `eval` calls on line 1), cross-source merging will pair the first AST and LLM finding, leaving the second separate.
- **Line Offset Variations:** Exact line matching (`line_start`) is preserved. If the LLM reports line 42 and AST reports line 43 for the same statement, they will not merge. A fuzzy window was considered but rejected to avoid false merges across consecutive lines.

---

## DEC-012: Phase 6b Celery Chord Callback Pattern and Inline Tier 2 Escalation

**Context:** Sections 3.2, 3.5.1, and 10.1 specify the end-to-end task workflow:
1. `orchestrate_pr_analysis` orchestrates fetching diff, preprocessing, parallel AST and LLM analysis, finding aggregation/deduplication, posting to GitHub, and database persistence.
2. AST and LLM analysis tasks run in parallel across chunks on the `cp-analysis` queue.
3. When critical findings with low or medium confidence are detected, Tier 2 escalation re-analyzes those chunks using `gemini-2.5-pro` before review comments are posted.

**Problem:**
In distributed Celery architectures, calling `.get()` or blocking on child subtasks inside an executing worker task is a known anti-pattern that risks worker pool deadlock: when all worker threads are blocked waiting for subtask completion, the child tasks cannot be picked up and processed.

**Decisions:**
1. **Celery Chord & Callback Chain:**
   - The analysis stage is structured as a Celery `chord`: the header executes a group of tasks (`analyze_ast_task` and `analyze_llm_task` for each chunk) in parallel on `cp-analysis`.
   - The chord callback is a 3-task chain: `aggregate_findings.s(...) | post_review_to_github.s() | persist_results.s()`.
   - Celery passes the accumulated results list from the chord header group as the first positional argument to `aggregate_findings`.
   - Subsequent tasks receive the dictionary output of the preceding task as their first argument.
2. **Inline Tier 2 Escalation:**
   - Instead of dispatching nested Celery tasks or dynamic sub-chords from inside `aggregate_findings` (which would require either blocking `.get()` or complex chord recursion), Tier 2 escalation re-analysis runs synchronously/inline inside `aggregate_findings` using `analyze_llm()` with model `gemini-2.5-pro`. This eliminates subtask `.get()` calls and keeps the task DAG strictly acyclic and deterministic.
3. **Single Source of Truth for Persistence:**
   - `persist_results` is the single place where database persistence occurs. `aggregate_and_post()` remains opt-in and does not persist by default.
4. **Posting Error Resilience:**
   - If `post_review_to_github` fails (e.g., GitHub API outage, 403, or rate limit), the error is caught, `github_review_id` is recorded as `None`, and the payload is forwarded to `persist_results` so that analysis findings and telemetry are never lost (§10.2).

---

## DEC-013: Phase 7a Pass-by-Reference Pipeline, Retries, Dead-Letter Handling, and Admin Retry

**Context:** Section 3.5.3, 3.5.4, 3.5.5, 3.7.2, and Section 10.2 specify production resilience guarantees:
1. Avoid passing megabyte-sized diffs and multi-finding review structures across Celery task message payloads in Redis.
2. Implement task-specific retry counts, exponential backoffs, and soft/hard timeouts matching §3.5.3 and §3.5.5.
3. Handle failure branches C (diff fetch), F (posting failure), G (postgres persistence failure), and H (worker crash mid-task).
4. Provide an authenticated administrative retry endpoint `POST /admin/retry-posting/{analysis_run_id}`.

**Decisions (Judgment Calls & Specifications):**
1. **Pass-by-Reference Pipeline (Redis Storage):**
   - Unified diffs and file patches are stored in Redis under keys `diff:{analysis_run_id}` and `pr_files:{analysis_run_id}` with a 24-hour TTL (86,400s per §3.7.2).
   - PR review payloads (containing summary body and formatted inline comments) are stored in Redis under `review_payload:{analysis_run_id}` with a 24-hour TTL.
   - Celery task signatures pass lightweight reference strings (`diff_ref`, `review_ref`, `files_ref`), keeping message broker payload sizes minimal and reducing memory usage.
2. **Durable Dead-Letter Storage for Admin Retry (Branch F):**
   - For Branch F (posting to GitHub fails and retries exhaust), relying solely on Redis for review payload retention would mean reviews could not be retried after the 24-hour Redis TTL expires.
   - Therefore, the full review payload is serialized into the PostgreSQL `dead_letter_log.task_args` JSONB column alongside task metadata.
   - Analysis findings remain safely committed to PostgreSQL with `status='completed'` and `review_posted_at=NULL`.
   - The admin endpoint loads the review payload directly from `dead_letter_log`, posts to GitHub, updates `analysis_runs.review_posted_at` and `github_review_id`, and marks `dead_letter_log.resolved=TRUE`.
3. **Branch G Persistence Fallback & Recovery:**
   - When PostgreSQL connection fails during `persist_results`, the task retries up to 3 times (1s, 3s, 9s backoff per §3.5.3).
   - If PostgreSQL is permanently down, findings, LLM telemetry, and run statistics are stored in Redis under `dead_letter:persist:{analysis_run_id}` and pushed to Redis queue `codepulse:pending_persistence` (7-day TTL).
   - Recovery function `recover_pending_persistence()` drains this queue and inserts all pending findings and metrics once PostgreSQL recovers.
4. **Terminal Status Invariant:**
   - Any task that exhausts retries or aborts permanently transitions `analysis_runs.status='failed'` with `error_message` recorded. An analysis run is never left in `"running"` or `"pending"`.
5. **Admin Retry Security:**
   - Authenticated via bearer token header matched against `ADMIN_API_KEY` using constant-time comparison (`hmac.compare_digest`).
   - If `ADMIN_API_KEY` is not set, the endpoint is disabled and returns HTTP 503.
   - If `ENVIRONMENT=production`, well-known development keys (`dev_admin_key_not_for_production`, `admin`, etc.) are rejected with HTTP 500.
6. **Failure Injection Isolation:**
   - Failure injection is strictly controlled by worker environment variables (`MOCK_POSTING_FAILURE`, `MOCK_DIFF_FETCH_FAILURE`, `MOCK_PERSIST_FAILURE`) and is honored only when `MOCK_GITHUB=true` or `MOCK_LLM=true`. Webhook headers and request payloads cannot trigger failure injection.
7. **Worker Log Privacy:**
   - Celery trace logging format `celery.app.trace.LOG_SUCCESS` is customized to omit `%(return_value)s`.
   - Application logger records strictly metadata (run IDs, repo names, PR numbers, file names, finding counts). Zero customer source code or diff lines are logged.
