"""Contract tests for real GitHub and Gemini API clients.

Uses httpx.MockTransport and mock SDK fixtures to verify exact HTTP request
construction, header contracts, response parsing, error mapping, pagination,
retryable status handling, and fallback behavior.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from codepulse.aggregation.github_poster import GitHubPoster, GitHubReviewPayload, ReviewCommentPayload
from codepulse.analysis.llm_client import GeminiClient, MockLLMClient, get_llm_client
from codepulse.analysis.llm_schemas import LLMResponse, Severity
from codepulse.ingestion.diff_fetcher import GitHubDiffFetcher, PRFile, create_github_app_jwt


# ── RSA Test Fixture ───────────────────────────────────────────────────


@pytest.fixture(scope="module")
def rsa_private_key_pem() -> bytes:
    """Generate a test 2048-bit RSA private key in PEM format."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ── In-Memory Fake Redis for Client Tests ──────────────────────────────


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, Any] = {}
        self.ttls: dict[str, int] = {}

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex

    def delete(self, *keys: str) -> None:
        for k in keys:
            self.store.pop(k, None)
            self.ttls.pop(k, None)


# ═══════════════════════════════════════════════════════════════════════
# 1. GitHub App JWT & Token Exchange Contract Tests
# ═══════════════════════════════════════════════════════════════════════


def test_github_app_jwt_structure_and_claims(rsa_private_key_pem: bytes):
    """Assert RS256 JWT header, backdated iat, 10m exp cap, and iss claim (§3.2.1)."""
    now = int(time.time())
    app_id = 98765
    token = create_github_app_jwt(app_id, rsa_private_key_pem)

    parts = token.split(".")
    assert len(parts) == 3, "JWT must contain header.payload.signature"

    # Decode header
    header_json = base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8")
    header = json.loads(header_json)
    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"

    # Decode payload claims
    payload_json = base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8")
    payload = json.loads(payload_json)
    assert payload["iss"] == "98765"
    assert abs(payload["iat"] - (now - 60)) <= 2, "iat must be backdated 60s"
    assert payload["exp"] - payload["iat"] <= 600, "exp must be at most 10m from iat"


def test_github_app_installation_token_exchange_and_caching(
    rsa_private_key_pem: bytes, tmp_path
):
    """Assert token exchange POST request, headers, and 55m Redis cache TTL."""
    key_file = tmp_path / "github_app.pem"
    key_file.write_bytes(rsa_private_key_pem)

    captured_requests: list[httpx.Request] = []

    def handle_request(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        if (
            request.method == "POST"
            and request.url.path == "/app/installations/4242/access_tokens"
        ):
            assert "Bearer " in request.headers["authorization"]
            assert request.headers["accept"] == "application/vnd.github+json"
            assert request.headers["x-github-api-version"] == "2022-11-28"
            return httpx.Response(
                201,
                json={
                    "token": "ghs_test_installation_token_xyz",
                    "expires_at": "2026-10-29T21:00:00Z",
                },
            )
        return httpx.Response(404)

    fake_redis = FakeRedis()
    fetcher = GitHubDiffFetcher(
        app_id=98765,
        private_key_path=str(key_file),
        redis_client=fake_redis,
        token_ttl=3300,  # 55 minutes
        transport=httpx.MockTransport(handle_request),
    )

    # First fetch exchanges JWT for installation token
    token1 = fetcher.get_installation_token(4242)
    assert token1 == "ghs_test_installation_token_xyz"
    assert len(captured_requests) == 1
    assert fake_redis.store["gh_token:4242"] == "ghs_test_installation_token_xyz"
    assert fake_redis.ttls["gh_token:4242"] == 3300

    # Second fetch must hit Redis cache without making an HTTP request
    token2 = fetcher.get_installation_token(4242)
    assert token2 == "ghs_test_installation_token_xyz"
    assert len(captured_requests) == 1


# ═══════════════════════════════════════════════════════════════════════
# 2. Diff Fetcher Contract Tests
# ═══════════════════════════════════════════════════════════════════════


def test_diff_fetcher_pagination_and_headers():
    """Assert pagination over pulls/{n}/files, rate limit extraction, and required headers."""
    captured_requests: list[httpx.Request] = []

    def handle_request(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        page = request.url.params.get("page", "1")
        headers = {
            "x-ratelimit-remaining": "4950",
            "x-ratelimit-reset": "1793285000",
        }
        if page == "1":
            # Page 1 returns 100 items
            items = [{"filename": f"src/file_{i}.py", "patch": "+code"} for i in range(100)]
            return httpx.Response(200, json=items, headers=headers)
        elif page == "2":
            # Page 2 returns 3 items
            items = [{"filename": f"src/file_{i}.py", "patch": "+code"} for i in range(100, 103)]
            return httpx.Response(200, json=items, headers=headers)
        return httpx.Response(200, json=[], headers=headers)

    fetcher = GitHubDiffFetcher(
        token="ghs_dummy_token",
        transport=httpx.MockTransport(handle_request),
    )

    files = fetcher.fetch_pr_files(owner="test-owner", repo="test-repo", pull_number=42)
    assert len(files) == 103
    assert len(captured_requests) == 2

    # Check headers on request
    assert captured_requests[0].headers["accept"] == "application/vnd.github+json"
    assert captured_requests[0].headers["x-github-api-version"] == "2022-11-28"
    assert captured_requests[0].headers["authorization"] == "Bearer ghs_dummy_token"

    # Check extracted rate limits
    assert fetcher.last_rate_limit_remaining == 4950
    assert fetcher.last_rate_limit_reset == 1793285000


def test_diff_fetcher_handles_files_without_patch():
    """Assert files with no patch (large diff or binary file) return patch=None."""
    def handle_request(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                {"filename": "images/logo.png", "status": "added", "patch": None},
                {"filename": "large_bundle.js", "status": "modified"},  # patch missing
            ],
        )

    fetcher = GitHubDiffFetcher(
        token="ghs_dummy_token",
        transport=httpx.MockTransport(handle_request),
    )

    files = fetcher.fetch_pr_files(owner="test-owner", repo="test-repo", pull_number=10)
    assert len(files) == 2
    assert files[0].filename == "images/logo.png"
    assert files[0].patch is None
    assert files[1].filename == "large_bundle.js"
    assert files[1].patch is None


def test_diff_fetcher_fetch_file_content_base64_decode():
    """Assert full file content fetch decodes base64 content with ref param."""
    captured: list[httpx.Request] = []

    def handle_request(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if request.url.path == "/repos/my-org/my-repo/contents/src/auth.py":
            assert request.url.params.get("ref") == "abcd123"
            content = "def login():\n    return True\n"
            b64_content = base64.b64encode(content.encode("utf-8")).decode("ascii")
            return httpx.Response(
                200,
                json={"content": b64_content, "encoding": "base64"},
            )
        return httpx.Response(404)

    fake_redis = FakeRedis()
    fetcher = GitHubDiffFetcher(
        token="ghs_token",
        redis_client=fake_redis,
        transport=httpx.MockTransport(handle_request),
    )

    content = fetcher.fetch_file_content(
        owner="my-org", repo="my-repo", path="src/auth.py", ref="abcd123"
    )
    assert content == "def login():\n    return True\n"
    assert len(captured) == 1

    # Missing file returns None on 404
    missing = fetcher.fetch_file_content(
        owner="my-org", repo="my-repo", path="nonexistent.py", ref="abcd123"
    )
    assert missing is None


def test_diff_fetcher_error_handling_403_and_500():
    """Assert HTTP 403 and 5xx errors raise httpx.HTTPStatusError."""
    def handle_request(request: httpx.Request) -> httpx.Response:
        if "403" in str(request.url):
            return httpx.Response(403, json={"message": "Resource rate limit exceeded"})
        return httpx.Response(502, json={"message": "Bad Gateway"})

    fetcher = GitHubDiffFetcher(
        token="ghs_token",
        transport=httpx.MockTransport(handle_request),
    )

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        fetcher.fetch_pr_files(owner="test", repo="403-repo", pull_number=1)
    assert exc_info.value.response.status_code == 403

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        fetcher.fetch_pr_files(owner="test", repo="502-repo", pull_number=1)
    assert exc_info.value.response.status_code == 502


# ═══════════════════════════════════════════════════════════════════════
# 3. Review Post Contract & Fallback Tests
# ═══════════════════════════════════════════════════════════════════════


def test_github_poster_successful_review():
    """Assert review payload structure and successful POST response."""
    captured: list[httpx.Request] = []

    def handle_request(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        data = json.loads(request.content)
        assert data["event"] == "COMMENT"
        assert data["body"] == "## Security Review"
        assert len(data["comments"]) == 1
        assert data["comments"][0]["path"] == "src/app.py"
        assert data["comments"][0]["line"] == 12
        assert data["comments"][0]["side"] == "RIGHT"
        return httpx.Response(
            200,
            json={
                "id": 998877,
                "html_url": "https://github.com/org/repo/pull/5#pullrequestreview-998877",
                "state": "COMMENT",
            },
        )

    poster = GitHubPoster(
        token="ghs_poster_token",
        transport=httpx.MockTransport(handle_request),
    )

    payload = GitHubReviewPayload(
        event="COMMENT",
        body="## Security Review",
        comments=[
            ReviewCommentPayload(
                path="src/app.py",
                line=12,
                side="RIGHT",
                body="Critical finding on line 12",
            )
        ],
    )

    res = poster.post_review("org", "repo", 5, payload)
    assert res["id"] == 998877
    assert len(captured) == 1
    assert captured[0].headers["authorization"] == "Bearer ghs_poster_token"


def test_github_poster_422_branch_f_fallback_to_summary_only():
    """Assert HTTP 422 triggers Branch F fallback: posts summary-only review without inline comments."""
    attempts: list[dict[str, Any]] = []

    def handle_request(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        attempts.append(data)
        if len(data.get("comments", [])) > 0:
            # First attempt with comments returns 422 Unprocessable Entity
            return httpx.Response(
                422,
                json={
                    "message": "Validation Failed",
                    "errors": ["Line 999 is outside the diff range."],
                },
            )
        else:
            # Second attempt with comments=[] (summary only) succeeds
            return httpx.Response(
                200,
                json={
                    "id": 554433,
                    "state": "COMMENT",
                    "body": data["body"],
                },
            )

    poster = GitHubPoster(
        token="ghs_token",
        transport=httpx.MockTransport(handle_request),
    )

    payload = {
        "event": "COMMENT",
        "body": "## Review Summary",
        "comments": [{"path": "src/bad.py", "line": 999, "side": "RIGHT", "body": "Bad line"}],
    }

    result = poster.post_review("org", "repo", 7, payload)
    assert result["id"] == 554433
    assert len(attempts) == 2
    assert len(attempts[0]["comments"]) == 1
    assert attempts[1]["comments"] == []
    assert attempts[1]["body"] == "## Review Summary"


def test_github_poster_raises_on_500_for_celery_retry():
    """Assert HTTP 500 raises httpx.HTTPStatusError for Celery retry backoff."""
    def handle_request(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "Internal Server Error"})

    poster = GitHubPoster(
        token="ghs_token",
        transport=httpx.MockTransport(handle_request),
    )

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        poster.post_review("org", "repo", 7, {"event": "COMMENT", "body": "test", "comments": []})
    assert exc_info.value.response.status_code == 500


# ═══════════════════════════════════════════════════════════════════════
# 4. Gemini Client Contract Tests
# ═══════════════════════════════════════════════════════════════════════


def test_gemini_client_request_configuration_and_token_mapping():
    """Assert GenerateContentConfig sets system_instruction, json schema, no tools, and maps tokens."""
    client = GeminiClient(api_key="test_key", default_model="gemini-3.7-flash")

    # Mock response from genai SDK
    mock_resp = MagicMock()
    mock_resp.text = json.dumps({
        "findings": [
            {
                "file_path": "src/app.py",
                "line_start": 5,
                "line_end": 5,
                "severity": "high",
                "category": "A03",
                "title": "SQL Injection",
                "explanation": "Unsanitized parameter",
                "remediation": "Use parameterized queries",
                "confidence": "high",
            }
        ]
    })
    mock_resp.candidates = [MagicMock(finish_reason="STOP")]
    mock_resp.usage_metadata.prompt_token_count = 142
    mock_resp.usage_metadata.candidates_token_count = 58

    mock_generate = MagicMock(return_value=mock_resp)
    client._genai_client.models.generate_content = mock_generate

    resp = client.analyze(
        system_instruction="You are a security auditor.",
        user_message="Analyze this diff.",
        model="gemini-3.7-flash",
    )

    # Assert request configuration
    mock_generate.assert_called_once()
    call_kwargs = mock_generate.call_args[1]
    assert call_kwargs["model"] == "gemini-3.7-flash"
    assert call_kwargs["contents"] == "Analyze this diff."

    config = call_kwargs["config"]
    assert config.system_instruction == "You are a security auditor."
    assert config.response_mime_type == "application/json"
    assert config.response_schema == LLMResponse
    assert config.tools is None, "Tools must be explicitly None (§3.4.7 defense #5)"

    # Assert parsed response and mapped token usage
    assert len(resp.findings) == 1
    assert resp.findings[0].severity == Severity.high
    assert resp.metadata.token_usage.input == 142
    assert resp.metadata.token_usage.output == 58
    assert resp.metadata.model_version == "gemini-3.7-flash"


def test_gemini_client_handles_configurable_models():
    """Assert GeminiClient correctly switches between gemini-3.7-flash and gemini-2.5-pro."""
    client = GeminiClient(api_key="test_key", default_model="gemini-3.7-flash")

    mock_resp = MagicMock()
    mock_resp.text = json.dumps({"findings": []})
    mock_resp.candidates = [MagicMock(finish_reason="STOP")]
    mock_resp.usage_metadata = None

    mock_generate = MagicMock(return_value=mock_resp)
    client._genai_client.models.generate_content = mock_generate

    # Call with gemini-2.5-pro
    resp = client.analyze(
        system_instruction="sys",
        user_message="msg",
        model="gemini-2.5-pro",
    )
    assert resp.metadata.model_version == "gemini-2.5-pro"
    assert mock_generate.call_args[1]["model"] == "gemini-2.5-pro"


def test_gemini_client_handles_safety_blocks():
    """Assert candidate finish_reason SAFETY raises RuntimeError."""
    client = GeminiClient(api_key="test_key")

    mock_resp = MagicMock()
    mock_resp.candidates = [MagicMock(finish_reason="SAFETY")]
    mock_resp.text = None

    client._genai_client.models.generate_content = MagicMock(return_value=mock_resp)

    with pytest.raises(RuntimeError, match="blocked by safety filters"):
        client.analyze("sys", "malicious payload")


def test_gemini_client_handles_truncated_invalid_json():
    """Assert truncated or invalid JSON raises ValueError."""
    client = GeminiClient(api_key="test_key")

    mock_resp = MagicMock()
    mock_resp.candidates = [MagicMock(finish_reason="STOP")]
    mock_resp.text = '{"findings": [{"file_path": "src/app.py", '  # Truncated JSON

    client._genai_client.models.generate_content = MagicMock(return_value=mock_resp)

    with pytest.raises(ValueError, match="Malformed or truncated JSON"):
        client.analyze("sys", "analyze")


def test_gemini_client_model_availability_verification():
    """Assert verify_model_availability queries models.get and returns bool."""
    client = GeminiClient(api_key="test_key")

    client._genai_client.models.get = MagicMock(return_value={"name": "gemini-3.7-flash"})
    assert client.verify_model_availability("gemini-3.7-flash") is True

    client._genai_client.models.get = MagicMock(side_effect=Exception("Model not found"))
    assert client.verify_model_availability("nonexistent-model") is False

    # Also test mock client availability
    mock_client = MockLLMClient()
    assert mock_client.verify_model_availability("gemini-3.7-flash") is True
    assert mock_client.verify_model_availability("gemini-2.5-pro") is True
    assert mock_client.verify_model_availability("unsupported-model") is False
