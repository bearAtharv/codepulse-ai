# CodePulse AI — Live Smoke-Test Runbook

This runbook provides human operators with step-by-step instructions to execute live, end-to-end smoke testing of CodePulse AI against real external APIs (GitHub REST API and Google Gemini API).

> [!IMPORTANT]
> **Zero Secrets Policy**: Never commit credentials, private keys, webhook secrets, or API tokens to git. All sensitive credentials must remain exclusively in the untracked local `.env` file or in a local secrets directory ignored by git.

---

## 1. Prerequisites & Setup

### 1.1 GitHub App Setup
1. In your GitHub organization or personal account, go to **Settings > Developer Settings > GitHub Apps > New GitHub App**.
2. Set configuration:
   - **GitHub App name**: `codepulse-ai-test-<your-username>`
   - **Homepage URL**: `https://github.com/your-org/codepulse-ai`
   - **Webhook URL**: Your active local ingress tunnel (see below).
   - **Webhook secret**: Generate a secure random string (e.g. `openssl rand -hex 24`).
3. Set Repository Permissions:
   - **Pull requests**: `Read and write`
   - **Contents**: `Read-only`
   - **Metadata**: `Read-only` (default)
4. Subscribe to Webhook Events:
   - Check `Pull request` events (`opened`, `synchronize`, `reopened`).
5. Generate and Download Private Key:
   - Click **Generate a private key**. Save the `.pem` file to a secure local location (e.g. `secrets/github_app.pem`).
   - Restrict permissions: `chmod 600 secrets/github_app.pem`.
6. Install GitHub App:
   - Under **Install App**, install the app on a dedicated test repository (e.g. `your-org/codepulse-smoke-test`). Note your numerical **Installation ID** from the URL (`/installations/<ID>`).

### 1.2 Webhook Tunnel Setup
Expose local port 8000 to the internet using a forwarding tunnel:

```bash
# Option A: Smee.io (Recommended for GitHub webhooks)
smee --url https://smee.io/<your-channel-id> --target http://127.0.0.1:8000/webhooks

# Option B: ngrok
ngrok http 8000

# Option C: Cloudflare Tunnel
cloudflared tunnel --url http://127.0.0.1:8000
```
Update your GitHub App's **Webhook URL** to the public tunnel endpoint (`.../webhooks`).

You can also simulate or smoke-test webhook ingress locally at any time without a tunnel using the built-in test script:
```bash
python3 scripts/send_test_webhook.py --repo "your-org/codepulse-smoke-test" --pr 1
```

### 1.3 Google Gemini API Key
Obtain an API key with access to `gemini-3.7-flash` and `gemini-2.5-pro` from [Google AI Studio](https://aistudio.google.com/).

---

## 2. Staged Smoke-Test Execution

We execute testing in two strictly isolated stages:
- **Stage 1**: Live GitHub App integration with Mock LLM (`MOCK_GITHUB=false, MOCK_LLM=true`).
- **Stage 2**: Full live integration with Live GitHub + Live Gemini (`MOCK_GITHUB=false, MOCK_LLM=false`).

---

### STAGE 1: Live GitHub Integration (Mock LLM)

**Objective**: Verify real GitHub App RS256 JWT signing, installation access token exchange, PR diff retrieval over the GitHub API, AST heuristic analysis, and review posting with inline comments to GitHub, without incurring LLM API costs.

#### 1. Exact Stage 1 `.env` Variable Names
The following are the exact variable names used by CodePulse AI during Stage 1:

- `ENVIRONMENT`
- `SERVICE_NAME`
- `POSTGRES_PASSWORD`
- `DATABASE_URL`
- `REDIS_PASSWORD`
- `REDIS_URL`
- `CELERY_BROKER_URL`
- `CELERY_RESULT_BACKEND`
- `MOCK_GITHUB`
- `MOCK_LLM`
- `GITHUB_APP_ID`
- `GITHUB_APP_PRIVATE_KEY_PATH`
- `GITHUB_WEBHOOK_SECRET`
- `ADMIN_API_KEY`
- `MOCK_LLM_FAILURE`
- `MOCK_RATE_LIMIT`
- `MOCK_GITHUB_RATE_LIMIT`
- `MOCK_POSTING_FAILURE`
- `MOCK_QUICK_RETRIES`

> [!NOTE]
> **Private Key Mounting:** The GitHub App RSA private key file must be placed in the local host directory `secrets/` (e.g. `secrets/github-app-key.pem`), which is mounted read-only into all containers at `/secrets/`. Inside Docker containers, `GITHUB_APP_PRIVATE_KEY_PATH` defaults to `/secrets/github-app-key.pem`. Ensure `chmod 600 secrets/github-app-key.pem` on the host.

#### 2. PostgreSQL Password & Volume Migration
When transitioning from `MOCK_GITHUB=true` (development mode allowing default password `codepulse_dev`) to `MOCK_GITHUB=false`, startup validation strictly rejects default credentials.
- **Action Required:**
  1. Define a secure, non-default `POSTGRES_PASSWORD` in `.env`.
  2. Ensure `DATABASE_URL` matches this password: `postgresql://codepulse:${POSTGRES_PASSWORD}@postgres:5432/codepulse`.
  3. If PostgreSQL was previously started with the default password, the existing Docker volume (`postgres_data`) retains the old password authentication database cluster.
  4. Run `docker compose down -v` to destroy the stale PostgreSQL volume, then `docker compose up -d --build` to re-initialize the database with the new credentials.
- **Data Lost:** All dev test run history, prior webhook operational logs, and ephemeral analysis records in PostgreSQL will be purged. (No production assets are lost as this is a local development/testing environment).

#### 3. Run Preflight Dry-Run Check
Always run the offline preflight verification script before launching containers:
```bash
python3 scripts/preflight_live.py
```
This dry-run confirms that all required environment variables are set, your GitHub App private key parses as a valid RSA key, secrets adhere to security rules, and confirms `[STAGE 1] Live GitHub App Integration (Mock LLM Client)` without calling external APIs or printing secret values.

#### 4. Start the Stack
```bash
docker compose down -v
docker compose up -d --build
docker compose ps
```

#### 5. Open Test Pull Request
In your test repository:
1. Create and checkout a test branch:
   ```bash
   git checkout -b test/codepulse-smoke-test-stage1
   ```
2. Create or edit `src/app.py` with known vulnerability patterns on lines 1–2:
   ```python
   data = eval(user_input)
   ```
3. Commit and push:
   ```bash
   git add src/app.py
   git commit -m "test: add eval vulnerability pattern for AST analysis"
   git push origin test/codepulse-smoke-test-stage1
   ```
4. Open a Pull Request from `test/codepulse-smoke-test-stage1` to `main`.

#### 6. What Success Looks Like

##### A. Expected Container Log Output
- **Web (`docker compose logs -f web`):**
  ```json
  {"timestamp": "...", "level": "INFO", "service": "codepulse-web", "logger": "codepulse.ingestion.webhook", "message": "Received webhook event=pull_request action=opened repo=your-org/your-repo delivery=... status=accepted"}
  ```
- **Worker (`docker compose logs -f worker`):**
  ```json
  {"timestamp": "...", "level": "INFO", "service": "codepulse-worker", "logger": "celery.worker.strategy", "message": "Task tasks.orchestrate_pr_analysis[...] received"}
  {"timestamp": "...", "level": "INFO", "service": "codepulse-worker", "logger": "codepulse.worker.tasks", "message": "Fetching diff for your-org/your-repo#..."}
  {"timestamp": "...", "level": "INFO", "service": "codepulse-worker", "logger": "codepulse.worker.tasks", "message": "Running AST analysis on 1 chunks"}
  {"timestamp": "...", "level": "INFO", "service": "codepulse-worker", "logger": "codepulse.worker.tasks", "message": "Using MockLLMClient (MOCK_LLM=true)"}
  {"timestamp": "...", "level": "INFO", "service": "codepulse-worker", "logger": "codepulse.worker.tasks", "message": "Aggregating findings for run ..."}
  {"timestamp": "...", "level": "INFO", "service": "codepulse-worker", "logger": "codepulse.aggregation.github_poster", "message": "Using GitHubPoster (MOCK_GITHUB=false)"}
  {"timestamp": "...", "level": "INFO", "service": "codepulse-worker", "logger": "codepulse.aggregation.github_poster", "message": "Posted review #<review_id> on your-org/your-repo#<pr_num> with 1 comments (event=COMMENT)"}
  {"timestamp": "...", "level": "INFO", "service": "codepulse-worker", "logger": "celery.app.trace", "message": "Task tasks.post_review_to_github[...] succeeded"}
  ```

##### B. Expected PostgreSQL Rows
Query PostgreSQL:
```bash
docker compose exec postgres psql -U codepulse -d codepulse -c \
  "SELECT id, status, review_posted_at, github_review_id, error_message, reanalysis_needed FROM analysis_runs ORDER BY created_at DESC LIMIT 1;"
```
- `status`: `completed`
- `review_posted_at`: Non-null ISO timestamp (e.g. `2026-11-01 17:05:00+00`)
- `github_review_id`: Numerical GitHub Review ID returned by GitHub (e.g. `1982736450`)
- `error_message`: `NULL`
- `reanalysis_needed`: `f` (false)

Verify findings status:
```bash
docker compose exec postgres psql -U codepulse -d codepulse -c \
  "SELECT file_path, line_start, severity, category, is_posted FROM findings WHERE analysis_run_id = (SELECT id FROM analysis_runs ORDER BY created_at DESC LIMIT 1);"
```
- `is_posted`: `t` (true) for all generated findings.

Verify dead letter queue:
```bash
docker compose exec postgres psql -U codepulse -d codepulse -c \
  "SELECT id, task_name, resolved FROM dead_letter_log WHERE created_at >= NOW() - INTERVAL '1 hour';"
```
- Returns 0 rows (no failed tasks entered dead letter queue).

#### 7. Troubleshooting Guide

| Issue / Symptom | Root Cause | Remediation Procedure |
| :--- | :--- | :--- |
| **HTTP 401 Unauthorized** on webhook delivery | `X-Hub-Signature-256` mismatch: HMAC SHA-256 signature generated by GitHub using the configured secret does not match `GITHUB_WEBHOOK_SECRET` in `.env`. | Verify that the secret string configured under GitHub App **Settings > Webhook secret** matches `GITHUB_WEBHOOK_SECRET` in `.env` character-for-character. Restart web container: `docker compose restart web`. |
| **HTTP 403 Forbidden: Installation Not Found or Suspended** | GitHub returns 403 when exchanging JWT for an installation token (`/app/installations/{id}/access_tokens`). The app is either not installed on the target repository, permissions are missing, or `GITHUB_APP_ID` is incorrect. | 1. Navigate to GitHub App settings -> **Install App** and confirm installation on the repository.<br>2. Confirm the numerical App ID in `.env` matches **App ID** on the GitHub App General page.<br>3. Check GitHub App permissions: ensure `Pull requests: Read & write` and `Contents: Read-only` are granted and accepted. |
| **HTTP 422 Unprocessable Entity (Diff Hunk Lines)** | GitHub Review API rejects inline review comments because line numbers fall outside unified diff hunks (`@@ -x,y +x,y @@`) or reference unchanged lines. | CodePulse AI automatically detects HTTP 422 and triggers Branch F fallback: the review comments are converted into a consolidated top-level review body (`comments=[]`) so the review is posted successfully. Verify worker logs for `GitHub rejected inline comments (422); falling back to top-level review body`. |
| **Tunnel Down / Connection Refused (GitHub Webhook Red Delivery)** | Local ingress forwarding tunnel (`smee`, `ngrok`, or `cloudflared`) disconnected, timed out, or crashed, causing GitHub webhook deliveries to fail with HTTP 502/504 or connection refused. | 1. Check tunnel terminal: restart `smee --url <url> --target http://127.0.0.1:8000/webhooks`.<br>2. Note the endpoint path is `/webhooks`.<br>3. In GitHub App settings, go to **Advanced > Recent Deliveries** and click **Redeliver** on the failed webhook. |
ser_input)
   cursor.execute(f"SELECT * FROM users WHERE name = '{data}'")
   ```
3. Commit, push, and open a PR against `main`:
   ```bash
   git add src/app.py
   git commit -m "test: trigger CodePulse smoke test"
   git push origin test/codepulse-smoke-test-stage1
   ```
4. Create the Pull Request in GitHub.

#### 4. Verification on GitHub
Inspect the newly opened PR in the GitHub web UI:
- **Bot Review**: A review appears authored by your GitHub App (`codepulse-ai-test[bot]`).
- **Review Event**: Posted as a `COMMENT` (no blocking approval or rejection).
- **Review Summary**: Contains summary title (`## CodePulse AI Security Review`), files analyzed count, and total findings.
- **Inline Comments**:
  - Comment on line 1: `eval` code injection warning.
  - Comment on line 2: SQL injection warning.

#### 5. Local Telemetry Verification
Run the following commands locally to verify data persistence and metrics:

```bash
# Check PostgreSQL analysis runs and findings
docker compose exec postgres psql -U codepulse -d codepulse -c \
  "SELECT id, repository, pull_number, status, total_findings, github_review_id, reanalysis_needed FROM analysis_runs ORDER BY created_at DESC LIMIT 1;"

# Check persisted findings
docker compose exec postgres psql -U codepulse -d codepulse -c \
  "SELECT file_path, line_start, severity, category, source, is_posted FROM findings ORDER BY id DESC LIMIT 5;"

# Check Prometheus metrics
curl -s http://127.0.0.1:9092/api/v1/query?query=codepulse_webhooks_received_total | jq .
curl -s http://127.0.0.1:9092/api/v1/query?query=codepulse_github_api_calls_total | jq .

# Check Loki container logs
curl -s -G http://127.0.0.1:3100/loki/api/v1/query_range \
  --data-urlencode 'query={service="codepulse-worker"} |= "post_review_to_github completed"' | jq .
```

---

### STAGE 2: Full Live Integration (Live GitHub + Live Gemini)

**Objective**: Verify the complete production pipeline with real Gemini API semantic analysis, structured JSON schema response enforcement, token accounting, cross-source deduplication, and GitHub review posting.

#### 1. Update Environment (`.env`)
Update the LLM configuration in `.env`:

```ini
# Enable Real Gemini API
MOCK_LLM=false
GEMINI_API_KEY=AIzaSy_your_real_gemini_api_key_here
GEMINI_MODEL=gemini-3.7-flash
GEMINI_RPM_LIMIT=324
GEMINI_RATE_LIMIT_DEADLINE=60.0
```

#### 2. Run Preflight Dry-Run Check
Verify Stage 2 configuration:
```bash
python3 scripts/preflight_live.py
```
This confirms `[STAGE 2] Full Live Integration (Live GitHub + Live Gemini API)` and validates `GEMINI_API_KEY` format without calling external APIs.

#### 3. Restart Worker & Web Services
```bash
docker compose restart web worker
```
Verify startup validation succeeded (no error logs regarding missing keys or insecure defaults):
```bash
docker compose logs --tail=30 web
docker compose logs --tail=30 worker
```

#### 4. Push a New Commit to the Pull Request
On your test branch, add an additional change to trigger a new commit analysis:

```bash
# Append an insecure function to src/app.py
cat << 'EOF' >> src/app.py

def unsafe_exec(cmd):
    import os
    os.system(cmd)
EOF

git add src/app.py
git commit -m "test: add command injection pattern for Gemini analysis"
git push origin test/codepulse-smoke-test-stage1
```

#### 5. Verification on GitHub
Inspect the updated PR in GitHub:
- A new review comment is posted for the new commit SHA.
- Findings reflect both AST pattern matches and Gemini semantic reasoning.
- Explanations and remediations contain model-generated guidance.

#### 6. Verify Gemini Telemetry & Usage Logs
Query the database and Prometheus to verify real token consumption:

```bash
# Verify LLM usage log in PostgreSQL
docker compose exec postgres psql -U codepulse -d codepulse -c \
  "SELECT model_version, input_tokens, output_tokens, latency_ms, cache_hit FROM llm_usage_log ORDER BY id DESC LIMIT 3;"

# Verify Prometheus token consumption metric
curl -s http://127.0.0.1:9092/api/v1/query?query=codepulse_llm_tokens_consumed_total | jq .

# Verify circuit breaker is CLOSED (0.0)
curl -s http://127.0.0.1:9092/api/v1/query?query=codepulse_circuit_breaker_state | jq .
```

---

### STAGE 3: Periodic Background Sweeps & Resilience (Celery Beat)

CodePulse AI runs scheduled periodic background sweeps on `codepulse-beat` to ensure complete resilience:

1. **Re-analysis of Degraded Runs (§6.4)**:
   - Task: `tasks.scan_reanalysis_needed` (every 5 minutes / 300s).
   - When Gemini experiences outages or trips the circuit breaker, runs proceed AST-only with `reanalysis_needed=True`.
   - Once Gemini recovers (breaker `CLOSED`), Beat triggers `tasks.scan_reanalysis_needed` to re-analyze diffs with LLM, merge confirmed findings, and post a follow-up review comment to GitHub.

2. **Unposted Review Recovery (§6.4, §10.2 Branch F)**:
   - Task: `tasks.scan_unposted_reviews` (every 10 minutes / 600s).
   - If GitHub API is down during initial analysis, `post_review_to_github` retries 5 times before durably persisting the review payload in `dead_letter_log` (`task_name=tasks.post_review_to_github`) with `analysis_runs.status='completed'` and `review_posted_at=NULL`.
   - Every 10 minutes, `scan_unposted_reviews` scans for completed runs older than 15 minutes with `review_posted_at IS NULL`, loads the durable Branch F review payload from `dead_letter_log`, and re-posts the review idempotently to GitHub, updating `review_posted_at`, `github_review_id`, and marking findings `is_posted=True`.

```bash
# Verify Celery Beat scheduler log firing periodic sweeps
docker compose logs --tail=50 beat | grep -E "scan-reanalysis-needed|scan-unposted-reviews"
```

---

## 3. Teardown, Revocation & Safety Protocol

Immediately following test completion, execute the following teardown steps to revoke credentials and prevent unwanted exposure:

1. **Stop Tunnels**: Terminate `smee`, `ngrok`, or `cloudflared` background processes.
2. **Uninstall GitHub App**: In your GitHub App settings, click **App settings > Advanced > Deactivate** or uninstall it from the test repository.
3. **Revoke Keys**:
   - In Google AI Studio, delete or rotate the test `GEMINI_API_KEY`.
   - In GitHub App settings, revoke the test RSA private key.
4. **Restore Local Defaults**:
   Revert `.env` to safe local development mock flags:
   ```ini
   MOCK_GITHUB=true
   MOCK_LLM=true
   GEMINI_API_KEY=
   ```
5. **Wipe Test Containers**:
   ```bash
   docker compose down -v
   ```
6. **Redaction Check**:
   Confirm no secrets were committed or logged:
   ```bash
   git status
   git diff
   grep -rn "AIzaSy" . --exclude-dir=.git
   ```
