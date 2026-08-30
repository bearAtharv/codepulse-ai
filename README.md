# CodePulse AI

**AI-powered code review that catches security vulnerabilities and memory leaks before they reach production.**

CodePulse AI is a GitHub App that automatically reviews pull requests using a combination of static analysis (AST-based pattern matching via tree-sitter) and LLM-powered analysis (Google Gemini). When a developer opens or updates a PR, CodePulse analyzes the changed code and posts inline review comments highlighting potential issues — complete with explanations and suggested fixes.

---

## Phase Status

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Project skeleton + data model | ✅ Done |
| **2** | Webhook ingestion service | 🔲 Planned |
| **3** | AST analysis engine (Python, JS/TS) | 🔲 Planned |
| **4** | LLM analysis engine (Gemini) | 🔲 Planned |
| **5** | Aggregation, dedup, GitHub review posting | 🔲 Planned |
| **6** | Celery orchestration wiring | 🔲 Planned |
| **7** | Failure handling (retry, circuit-breaker, dead-letter) | 🔲 Planned |
| **8** | Kubernetes/Helm + observability | 🔲 Planned |

---

## How It Works

When a pull request is opened on a connected repository, GitHub sends a webhook to CodePulse. The system verifies the webhook signature, checks for duplicates, and kicks off a background analysis pipeline. That pipeline fetches the PR diff, runs both AST and LLM analysis in parallel, deduplicates the findings, and posts the results as GitHub review comments.

### High-Level Architecture

```mermaid
flowchart LR
    GH["GitHub\n(Webhooks + API)"]
    WS["Webhook Service\n(FastAPI)"]
    RD[("Redis\n(Broker + Cache)")]
    CW["Celery Workers"]
    AST["AST Engine\n(tree-sitter)"]
    LLM["Gemini API"]
    AGG["Aggregator\n+ Dedup"]
    PG[("PostgreSQL")]

    GH -- "PR event\n(webhook)" --> WS
    WS -- "Enqueue task" --> RD
    WS -- "Upsert repo\n+ analysis_run" --> PG
    RD -- "Consume" --> CW
    CW -- "Fetch diff\n+ files" --> GH
    CW --> AST
    CW --> LLM
    AST -- "Findings" --> AGG
    LLM -- "Findings" --> AGG
    AGG -- "Store" --> PG
    AGG -- "Post review\ncomments" --> GH
```

### Pipeline Sequence

This shows the full lifecycle of a single pull request event, from webhook receipt to review comments appearing on GitHub:

```mermaid
sequenceDiagram
    participant GH as GitHub
    participant WS as Webhook Service
    participant RD as Redis
    participant CW as Celery Worker
    participant AST as AST Engine
    participant LLM as Gemini API
    participant PG as PostgreSQL

    GH->>WS: POST /webhooks (PR event)
    WS->>WS: Verify HMAC-SHA256 signature
    WS->>RD: SET NX idempotency check
    alt Duplicate
        RD-->>WS: Key exists
        WS-->>GH: 200 OK (skip)
    else New event
        RD-->>WS: Key set
        WS->>PG: Upsert repo + create analysis_run
        WS->>RD: Enqueue orchestrate_pr_analysis
        WS-->>GH: 202 Accepted
    end

    RD->>CW: Deliver task
    CW->>GH: Fetch PR diff + file contents
    CW->>CW: Chunk files by function/class

    par Static Analysis
        CW->>AST: Parse chunks with tree-sitter
        AST-->>CW: AST findings
    and LLM Analysis
        CW->>LLM: Send chunks + prompt
        LLM-->>CW: LLM findings
    end

    CW->>CW: Aggregate + deduplicate
    CW->>PG: Store findings
    CW->>GH: Post review comments
    CW->>PG: Update analysis_run status
```

### Database Schema

Six tables track everything from repository metadata to individual findings and operational telemetry:

```mermaid
erDiagram
    repositories ||--o{ analysis_runs : "has many"
    analysis_runs ||--o{ findings : "produces"
    analysis_runs ||--o{ llm_usage_log : "tracks"

    repositories {
        bigserial id PK
        bigint github_id UK
        varchar full_name
        bigint installation_id
        varchar default_branch
        varchar primary_language
        timestamptz created_at
        timestamptz updated_at
    }

    analysis_runs {
        uuid id PK
        bigint repository_id FK
        int pull_request_number
        varchar head_sha
        varchar base_sha
        varchar pr_author
        varchar status
        int total_findings
        boolean reanalysis_needed
        timestamptz webhook_received_at
        timestamptz completed_at
        timestamptz created_at
    }

    findings {
        uuid id PK
        uuid analysis_run_id FK
        varchar file_path
        int line_start
        int line_end
        varchar severity
        varchar category
        varchar title
        text explanation
        text suggested_fix
        text remediation
        varchar confidence
        varchar source
        boolean is_posted
        timestamptz created_at
    }

    llm_usage_log {
        bigserial id PK
        uuid analysis_run_id FK
        varchar model_version
        int input_tokens
        int output_tokens
        int latency_ms
        boolean cache_hit
        timestamptz created_at
    }

    dead_letter_log {
        bigserial id PK
        varchar task_name
        uuid task_id
        jsonb task_args
        varchar exception_type
        text exception_message
        int retry_count
        boolean resolved
        timestamptz created_at
    }

    webhook_events_log {
        bigserial id PK
        uuid delivery_id UK
        varchar event_type
        varchar action
        varchar repository_full_name
        boolean processed
        boolean duplicate
        timestamptz received_at
    }
```

---

## What's Implemented

### Phase 1 — Project Skeleton + Data Model

- **Poetry** for dependency management (Python 3.12, FastAPI, Celery, SQLAlchemy, Alembic, Redis, Pydantic)
- **Docker Compose** with PostgreSQL 16 and Redis 7.2 for local development
- **Alembic migrations** creating all 6 tables with proper constraints, indexes, and foreign keys
- **SQLAlchemy ORM models** with full relationship mappings
- **Pydantic settings** loading all configuration from environment variables
- **30 unit tests** validating model metadata, constraints, and instantiation

---

## Getting Started

### Prerequisites

- **Docker Desktop** (for PostgreSQL and Redis)
- **Python 3.12+** (for running tests locally)
- **Poetry** (`pip install poetry`)

### Run the Stack

```bash
# Start Postgres + Redis and run migrations
docker compose up --build -d

# Verify the schema
PYTHONPATH=src python scripts/verify_schema.py
```

### Run Tests

```bash
# Install dev dependencies
poetry install

# Run all tests (no Docker needed)
PYTHONPATH=src python -m pytest tests/ -v
```

---

## Project Structure

```
src/codepulse/
├── config.py                 # Pydantic settings (env vars)
├── models/
│   ├── base.py               # SQLAlchemy DeclarativeBase
│   └── tables.py             # All 6 ORM models
├── persistence/
│   └── database.py           # Engine + session factory
├── ingestion/                # Phase 2: webhook service
├── worker/                   # Phase 6: Celery orchestration
├── analysis/                 # Phase 3-4: AST + LLM engines
├── aggregation/              # Phase 5: dedup + review posting
└── common/                   # Shared utilities
```

---

## Design Decisions

See [DECISIONS.md](DECISIONS.md) for a log of all architecture decisions, especially where the implementation diverges from or clarifies the architecture document.
