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
smee --url https://smee.io/<your-channel-id> --target http://127.0.0.1:8000/webhook

# Option B: ngrok
ngrok http 8000

# Option C: Cloudflare Tunnel
cloudflared tunnel --url http://127.0.0.1:8000
```
Update your GitHub App's **Webhook URL** to the public tunnel endpoint (`.../webhook`).

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

#### 1. Configure Local Environment (`.env`)
Edit your untracked `.env` file:

```ini
ENVIRONMENT=development
SERVICE_NAME=codepulse

# Database & Broker Credentials
POSTGRES_PASSWORD=your_secure_postgres_password_here
DATABASE_URL=postgresql://codepulse:your_secure_postgres_password_here@127.0.0.1:5432/codepulse
REDIS_PASSWORD=your_secure_redis_password_here
REDIS_URL=redis://:your_secure_redis_password_here@127.0.0.1:6379/0
CELERY_BROKER_URL=redis://:your_secure_redis_password_here@127.0.0.1:6379/0
CELERY_RESULT_BACKEND=redis://:your_secure_redis_password_here@127.0.0.1:6379/0

# GitHub App Live Credentials
MOCK_GITHUB=false
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_PATH=/absolute/path/to/secrets/github_app.pem
GITHUB_WEBHOOK_SECRET=your_configured_webhook_secret_here
ADMIN_API_KEY=your_secure_admin_api_key_here

# LLM in Mock Mode
MOCK_LLM=true
GEMINI_API_KEY=
GEMINI_MODEL=gemini-3.7-flash

# Ensure failure injection flags are false
MOCK_LLM_FAILURE=false
MOCK_RATE_LIMIT=false
MOCK_GITHUB_RATE_LIMIT=false
MOCK_POSTING_FAILURE=false
MOCK_QUICK_RETRIES=false
```

#### 2. Start the Stack
```bash
docker compose down -v
docker compose up -d --build
docker compose ps
```

#### 3. Open Test Pull Request
In your test repository:
1. Create and checkout a test branch:
   ```bash
   git checkout -b test/codepulse-smoke-test-stage1
   ```
2. Create or edit `src/app.py` with known vulnerability patterns on lines 1–2:
   ```python
   data = eval(user_input)
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

#### 2. Restart Worker & Web Services
```bash
docker compose restart web worker
```
Verify startup validation succeeded (no error logs regarding missing keys or insecure defaults):
```bash
docker compose logs --tail=30 web
docker compose logs --tail=30 worker
```

#### 3. Push a New Commit to the Pull Request
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

#### 4. Verification on GitHub
Inspect the updated PR in GitHub:
- A new review comment is posted for the new commit SHA.
- Findings reflect both AST pattern matches and Gemini semantic reasoning.
- Explanations and remediations contain model-generated guidance.

#### 5. Verify Gemini Telemetry & Usage Logs
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
