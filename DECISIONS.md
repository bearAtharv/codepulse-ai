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
