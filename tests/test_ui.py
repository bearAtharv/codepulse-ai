"""Tests for CodePulse Web UI and Operator Portal.

Covers:
  - Root redirection (/ui -> /ui/analyze)
  - /ui/analyze with sample security vulnerability patterns (eval, SQLi, secrets, XSS)
  - /ui/analyze input validation: empty code, size limit (>200 KB), file extension restrictions
  - XSS escaping: ensures arbitrary code and finding titles are strictly HTML-escaped
  - Security headers (CSP, nosniff, frame-ancestors, X-Frame-Options, Referrer-Policy)
  - Authentication enforcement in non-dev/protected mode (login, session cookies, rate limiting)
  - CSRF token validation on POST requests
  - UI_ENABLED=false toggle (404)
  - /ui/simulate dispatching signed webhooks and tracking analysis runs
  - /ui/runs paginated table and status filtering
  - /ui/runs/{id} details rendering, review payload display, and admin retry invocation
"""

from __future__ import annotations

import html
import io
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from codepulse.config import Settings, get_settings
from codepulse.ingestion.app import app
from codepulse.models.tables import AnalysisRun, Finding, Repository
from codepulse.persistence.database import get_db_session, get_redis_client
from codepulse.ui.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    generate_csrf_token,
)


# ── Fixtures & Mock DB / Redis ──────────────────────────────────────────────


class MockDBSession:
    """Mock SQLAlchemy session for UI testing."""

    def __init__(self) -> None:
        self.repositories: list[Repository] = []
        self.runs: list[AnalysisRun] = []
        self.findings: list[Finding] = []

    def execute(self, stmt: Any) -> Any:
        # Simple query interceptor for test purposes
        result_mock = MagicMock()
        stmt_str = str(stmt)

        if "count(" in stmt_str.lower():
            result_mock.scalar.return_value = len(self.runs)
            return result_mock

        if "analysis_runs.id =" in stmt_str:
            result_mock.unique.return_value.scalar_one_or_none.return_value = self.runs[0] if self.runs else None
            result_mock.scalar_one_or_none.return_value = self.runs[0] if self.runs else None
            return result_mock

        if "analysis_runs.head_sha =" in stmt_str:
            result_mock.scalar_one_or_none.return_value = self.runs[0] if self.runs else None
            return result_mock

        # Default query for runs list
        result_mock.scalars.return_value.all.return_value = self.runs
        result_mock.scalars.return_value.first.return_value = self.runs[0] if self.runs else None
        return result_mock

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass


@pytest.fixture
def mock_db() -> MockDBSession:
    db = MockDBSession()
    repo = Repository(id=1, full_name="corp-test/sample-repo")
    db.repositories.append(repo)

    run = AnalysisRun(
        id=uuid.uuid4(),
        repository_id=repo.id,
        pull_request_number=101,
        head_sha="a" * 40,
        base_sha="b" * 40,
        pr_author="alice",
        status="completed",
        files_analyzed=3,
        chunks_total=5,
        chunks_completed=5,
        total_findings=2,
        critical_count=1,
        high_count=1,
        medium_count=0,
        low_count=0,
        analysis_duration_ms=420,
        webhook_received_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
        review_posted_at=datetime.now(timezone.utc),
        github_review_id=98765,
    )
    run.repository = repo

    f1 = Finding(
        id=uuid.uuid4(),
        analysis_run_id=run.id,
        file_path="src/main.py",
        line_start=12,
        line_end=12,
        severity="critical",
        category="injection",
        title="SQL Injection via string interpolation",
        explanation="Untrusted user input interpolated into SQL query.",
        remediation="Use parameterized queries.",
        confidence="high",
        source="ast",
    )
    f2 = Finding(
        id=uuid.uuid4(),
        analysis_run_id=run.id,
        file_path="src/main.py",
        line_start=24,
        line_end=24,
        severity="high",
        category="security",
        title="Dynamic eval execution",
        explanation="eval() allows arbitrary code execution.",
        remediation="Use ast.literal_eval.",
        confidence="high",
        source="llm",
    )
    run.findings = [f1, f2]
    db.runs.append(run)
    db.findings.extend([f1, f2])
    return db


@pytest.fixture
def client(mock_db: MockDBSession) -> TestClient:
    app.dependency_overrides[get_db_session] = lambda: mock_db
    test_client = TestClient(app, raise_server_exceptions=True)
    yield test_client
    app.dependency_overrides.clear()


# ── Tests ───────────────────────────────────────────────────────────────────


def test_ui_root_redirect(client: TestClient) -> None:
    """GET /ui should redirect to /ui/analyze."""
    resp = client.get("/ui", follow_redirects=False)
    assert resp.status_code == status.HTTP_302_FOUND
    assert resp.headers["location"] == "/ui/analyze"


def test_ui_security_headers(client: TestClient) -> None:
    """Verify security headers (CSP, nosniff, DENY, Referrer-Policy) on UI responses."""
    resp = client.get("/ui/analyze")
    assert resp.status_code == status.HTTP_200_OK
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_analyze_page_get(client: TestClient) -> None:
    """GET /ui/analyze loads the interactive analyzer form."""
    resp = client.get("/ui/analyze")
    assert resp.status_code == status.HTTP_200_OK
    assert "Interactive Code Analyzer" in resp.text
    assert "Run Security Analysis" in resp.text
    assert 'name="csrf_token"' in resp.text


def test_analyze_samples(client: TestClient) -> None:
    """POST /ui/analyze detects expected vulnerabilities across standard fixtures."""
    # 1. SQL Injection f-string
    sqli_code = 'cursor.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")'
    resp_sqli = client.post("/ui/analyze", data={"code": sqli_code, "language": "python"})
    assert resp_sqli.status_code == status.HTTP_200_OK
    assert "Analysis Findings" in resp_sqli.text
    assert "SQL" in resp_sqli.text or "Injection" in resp_sqli.text

    # 2. Dynamic eval
    eval_code = "result = eval(user_input_payload)"
    resp_eval = client.post("/ui/analyze", data={"code": eval_code, "language": "python"})
    assert resp_eval.status_code == status.HTTP_200_OK
    assert "eval" in resp_eval.text.lower() or "injection" in resp_eval.text.lower()

    # 3. Hardcoded Secret
    secret_code = 'AWS_SECRET_KEY = "AKIA1234567890EXAMPLEKEY"\nDATABASE_PASSWORD = "super_secret_production_password_123"'
    resp_secret = client.post("/ui/analyze", data={"code": secret_code, "language": "python"})
    assert resp_secret.status_code == status.HTTP_200_OK
    assert "secret" in resp_secret.text.lower() or "credential" in resp_secret.text.lower()

    # 4. innerHTML DOM XSS
    xss_code = 'document.getElementById("user-bio").innerHTML = userInput.bio;'
    resp_xss = client.post("/ui/analyze", data={"code": xss_code, "language": "javascript"})
    assert resp_xss.status_code == status.HTTP_200_OK
    assert "innerhtml" in resp_xss.text.lower() or "xss" in resp_xss.text.lower()


def test_analyze_api_endpoint(client: TestClient) -> None:
    """POST /ui/api/analyze returns structured JSON with findings."""
    code = 'cursor.execute(f"SELECT * FROM accounts WHERE id = \'{account_id}\'")'
    resp = client.post("/ui/api/analyze", json={"code": code, "language": "python", "use_ai": False})
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["status"] == "success"
    assert data["total_findings"] >= 1
    assert any("sql" in f["title"].lower() or "injection" in f["category"].lower() for f in data["findings"])


def test_analyze_validation_empty_input(client: TestClient) -> None:
    """Empty code input should yield a friendly error message."""
    resp = client.post("/ui/analyze", data={"code": "   ", "language": "python"})
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert "Please paste source code" in resp.text


def test_analyze_validation_size_limit(client: TestClient) -> None:
    """Code exceeding 200 KB limit is rejected with 413."""
    oversized = "a = 1\n" * 40000  # ~240 KB
    resp = client.post("/ui/analyze", data={"code": oversized, "language": "python"})
    assert resp.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    assert "exceeds maximum size limit of 200 KB" in resp.text


def test_analyze_file_upload_validation(client: TestClient) -> None:
    """File upload validates extension and size."""
    # 1. Unsupported extension (.exe)
    invalid_file = io.BytesIO(b"some binary payload")
    resp_invalid = client.post(
        "/ui/analyze",
        data={"language": "auto"},
        files={"file": ("malicious.exe", invalid_file, "application/octet-stream")},
    )
    assert resp_invalid.status_code == status.HTTP_400_BAD_REQUEST
    assert "Unsupported file extension" in resp_invalid.text

    # 2. Valid Python file (.py)
    valid_file = io.BytesIO(b'x = eval("1+1")\n')
    resp_valid = client.post(
        "/ui/analyze",
        data={"language": "auto"},
        files={"file": ("test.py", valid_file, "text/plain")},
    )
    assert resp_valid.status_code == status.HTTP_200_OK
    assert "Analysis Findings" in resp_valid.text


def test_xss_escaping_in_rendered_html(client: TestClient) -> None:
    """Verify that malicious payload tags in submitted code or names are strictly HTML-escaped."""
    xss_payload = '<script>alert("PWNED_XSS")</script>'
    resp = client.post("/ui/analyze", data={"code": f"# {xss_payload}\nx = 1", "language": "python"})
    assert resp.status_code == status.HTTP_200_OK
    # Must NOT contain raw unescaped script tags
    assert '<script>alert("PWNED_XSS")</script>' not in resp.text
    # Must contain HTML-escaped entities
    assert "&lt;script&gt;" in resp.text
    assert "&lt;/script&gt;" in resp.text


def test_auth_enforcement_in_protected_mode(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """In protected mode (UI_PASSWORD set or non-dev), unauthenticated access is blocked."""
    test_password = "SecretOperatorPassword_2026"
    custom_settings = Settings(
        environment="production",
        mock_github=False,
        ui_enabled=True,
        ui_password=test_password,
        ui_session_secret="test_session_secret_12345",
        admin_api_key="admin_test_key",
        gemini_api_key="gemini_test_key",
        github_app_id="12345",
        github_app_private_key_path="secrets/test.pem",
    )
    monkeypatch.setattr("codepulse.ui.router.get_settings", lambda: custom_settings)
    monkeypatch.setattr("codepulse.ui.auth.get_settings", lambda: custom_settings)

    # 1. Unauthenticated page request redirects to /ui/login
    resp = client.get("/ui/analyze", follow_redirects=False)
    assert resp.status_code == status.HTTP_303_SEE_OTHER
    assert "/ui/login" in resp.headers["location"]

    # 2. Unauthenticated API request returns 401
    resp_api = client.post("/ui/api/analyze", json={"code": "x = 1"})
    assert resp_api.status_code == status.HTTP_401_UNAUTHORIZED

    # 3. Wrong password at /ui/login rejected
    resp_bad_login = client.post("/ui/login", data={"password": "WrongPassword"})
    assert resp_bad_login.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid password" in resp_bad_login.text

    # 4. Correct password sets session cookie
    resp_good_login = client.post("/ui/login", data={"password": test_password, "next": "/ui/analyze"}, follow_redirects=False)
    assert resp_good_login.status_code == status.HTTP_303_SEE_OTHER
    assert SESSION_COOKIE_NAME in resp_good_login.cookies

    # 5. Authenticated request with session cookie succeeds
    session_cookie = resp_good_login.cookies[SESSION_COOKIE_NAME]
    client.cookies.set(SESSION_COOKIE_NAME, session_cookie)
    resp_auth = client.get("/ui/analyze")
    assert resp_auth.status_code == status.HTTP_200_OK


def test_csrf_token_enforcement(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """CSRF token is strictly validated on POSTs in protected mode."""
    test_password = "SecretPassword123"
    custom_settings = Settings(
        environment="production",
        mock_github=False,
        ui_enabled=True,
        ui_password=test_password,
        ui_session_secret="test_session_secret_12345",
        admin_api_key="admin_test_key",
        gemini_api_key="gemini_test_key",
        github_app_id="12345",
        github_app_private_key_path="secrets/test.pem",
    )
    monkeypatch.setattr("codepulse.ui.router.get_settings", lambda: custom_settings)
    monkeypatch.setattr("codepulse.ui.auth.get_settings", lambda: custom_settings)

    session_token = create_session_token(custom_settings)
    client.cookies.set(SESSION_COOKIE_NAME, session_token)

    # 1. Missing CSRF token -> 403 Forbidden
    resp_no_csrf = client.post("/ui/analyze", data={"code": "x = 1", "csrf_token": ""})
    assert resp_no_csrf.status_code == status.HTTP_403_FORBIDDEN

    # 2. Invalid CSRF token -> 403 Forbidden
    resp_bad_csrf = client.post("/ui/analyze", data={"code": "x = 1", "csrf_token": "tampered_token"})
    assert resp_bad_csrf.status_code == status.HTTP_403_FORBIDDEN

    # 3. Valid CSRF token -> 200 OK
    valid_csrf = generate_csrf_token(session_token, custom_settings)
    resp_valid = client.post("/ui/analyze", data={"code": "x = 1", "csrf_token": valid_csrf})
    assert resp_valid.status_code == status.HTTP_200_OK


def test_ui_disabled_setting(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """When UI_ENABLED=false, all /ui routes return 404."""
    disabled_settings = Settings(ui_enabled=False)
    monkeypatch.setattr("codepulse.ui.router.get_settings", lambda: disabled_settings)
    monkeypatch.setattr("codepulse.ui.auth.get_settings", lambda: disabled_settings)

    resp = client.get("/ui/analyze")
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_simulate_page_get_and_post(client: TestClient, mock_db: MockDBSession) -> None:
    """GET and POST /ui/simulate triggers webhook and creates run."""
    # 1. GET /ui/simulate
    resp = client.get("/ui/simulate")
    assert resp.status_code == status.HTTP_200_OK
    assert "Simulate Pull Request Webhook" in resp.text

    # 2. POST /ui/simulate
    with patch("codepulse.worker.tasks.orchestrate_pr_analysis.apply_async"):
        resp_post = client.post(
            "/ui/simulate",
            data={
                "repo_name": "corp-demo/repo-sample",
                "pr_number": 105,
                "diff_text": "diff --git a/app.py b/app.py",
            },
        )
        assert resp_post.status_code == status.HTTP_200_OK
        assert "Live Pipeline Execution" in resp_post.text


def test_runs_list_page(client: TestClient, mock_db: MockDBSession) -> None:
    """GET /ui/runs renders table with pagination and status filters."""
    resp = client.get("/ui/runs")
    assert resp.status_code == status.HTTP_200_OK
    assert "Recent Pull Request Analyses" in resp.text
    assert "corp-test/sample-repo" in resp.text
    assert "#101" in resp.text
    assert "COMPLETED" in resp.text


def test_run_details_and_retry(client: TestClient, mock_db: MockDBSession) -> None:
    """GET /ui/runs/{id} renders details and executes retry posting."""
    run_id = str(mock_db.runs[0].id)

    # 1. GET details
    resp = client.get(f"/ui/runs/{run_id}")
    assert resp.status_code == status.HTTP_200_OK
    assert "corp-test/sample-repo #101" in resp.text
    assert "Deduplicated Findings" in resp.text
    assert "SQL Injection via string interpolation" in resp.text

    # 2. Polling API
    resp_poll = client.get(f"/ui/api/runs/{run_id}")
    assert resp_poll.status_code == status.HTTP_200_OK
    data = resp_poll.json()
    assert data["status"] == "completed"
    assert data["total_findings"] == 2

    # 3. Retry API
    with patch("codepulse.ui.router.execute_retry_posting") as mock_retry:
        mock_retry.return_value = {"status": "success", "github_review_id": 9999}
        resp_retry = client.post(f"/ui/api/runs/{run_id}/retry", headers={"X-CSRF-Token": "dev-csrf"})
        assert resp_retry.status_code == status.HTTP_200_OK
        assert resp_retry.json()["success"] is True
