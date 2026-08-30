"""Tests for the webhook ingestion service (Phase 2).

Covers:
  - HMAC-SHA256 signature verification (pure function)
  - Event filtering (ping, accepted/rejected PR actions, unknown events)
  - Redis-based idempotency (duplicate rejection via SET NX)
  - DB-level idempotency fallback
  - Celery task enqueue with correct kwargs
  - Health / readiness endpoints

All tests run WITHOUT external dependencies (no Redis, Postgres, or Celery).
Dependencies are replaced via FastAPI dependency overrides and unittest.mock.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from codepulse.config import Settings
from codepulse.ingestion.app import app
from codepulse.ingestion.dependencies import (
    get_db_session,
    get_redis_client,
    get_settings_dep,
)
from codepulse.ingestion.signature import verify_webhook_signature


# ── Helpers & fixtures ───────────────────────────────────────────────────────

WEBHOOK_SECRET = "test_webhook_secret_12345"


class FakeRedis:
    """Minimal Redis mock supporting SET NX for idempotency tests."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def set(
        self, name: str, value: str, *, nx: bool = False, ex: int | None = None
    ) -> bool:
        if nx and name in self._store:
            return False
        self._store[name] = value
        return True

    def get(self, name: str) -> str | None:
        return self._store.get(name)

    def ping(self) -> bool:
        return True


def make_pr_payload(
    *,
    action: str = "opened",
    pr_number: int = 42,
    head_sha: str = "a" * 40,
    base_sha: str = "b" * 40,
    repo_name: str = "owner/repo",
    repo_id: int = 12345,
    installation_id: int = 67890,
    pr_author: str = "developer",
) -> dict:
    """Build a realistic GitHub ``pull_request`` webhook payload."""
    return {
        "action": action,
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "head": {"sha": head_sha},
            "base": {"sha": base_sha},
            "user": {"login": pr_author},
        },
        "repository": {
            "id": repo_id,
            "full_name": repo_name,
            "default_branch": "main",
            "language": "Python",
        },
        "installation": {"id": installation_id},
    }


def sign_payload(payload_bytes: bytes, secret: str = WEBHOOK_SECRET) -> str:
    """Compute ``X-Hub-Signature-256`` header value."""
    return "sha256=" + hmac.new(
        secret.encode("utf-8"), payload_bytes, hashlib.sha256
    ).hexdigest()


def make_headers(
    payload_bytes: bytes,
    *,
    event: str = "pull_request",
    secret: str = WEBHOOK_SECRET,
    delivery_id: str | None = None,
) -> dict[str, str]:
    """Build complete GitHub webhook request headers."""
    return {
        "X-Hub-Signature-256": sign_payload(payload_bytes, secret),
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery_id or str(uuid.uuid4()),
        "Content-Type": "application/json",
    }


@pytest.fixture()
def fake_redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture()
def mock_db() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def mock_service():
    """Patch the ``service`` module used by the webhook handler."""
    with patch("codepulse.ingestion.webhook.service") as svc:
        svc.upsert_repository.return_value = 1
        svc.create_analysis_run.return_value = uuid.uuid4()
        yield svc


@pytest.fixture()
def mock_task():
    """Patch the Celery task imported by the webhook handler."""
    with patch("codepulse.ingestion.webhook.orchestrate_pr_analysis") as task:
        yield task


@pytest.fixture()
def client(fake_redis, mock_db) -> TestClient:
    """FastAPI test client with mocked Redis, DB, and settings."""
    test_settings = Settings(
        database_url="postgresql://test:test@localhost/test",
        redis_url="redis://localhost:6379/0",
        github_webhook_secret=WEBHOOK_SECRET,
        mock_github=True,
        mock_llm=True,
    )

    app.dependency_overrides[get_redis_client] = lambda: fake_redis
    app.dependency_overrides[get_db_session] = lambda: mock_db
    app.dependency_overrides[get_settings_dep] = lambda: test_settings

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


# ── Signature verification (pure function) ────────────────────────────────────


class TestSignatureVerification:
    """Direct tests for ``verify_webhook_signature``."""

    def test_valid_signature(self) -> None:
        body = b'{"test": true}'
        sig = sign_payload(body)
        assert verify_webhook_signature(body, sig, WEBHOOK_SECRET) is True

    def test_invalid_signature(self) -> None:
        body = b'{"test": true}'
        assert verify_webhook_signature(body, "sha256=invalid", WEBHOOK_SECRET) is False

    def test_wrong_secret(self) -> None:
        body = b'{"test": true}'
        sig = sign_payload(body, "correct_secret")
        assert verify_webhook_signature(body, sig, "wrong_secret") is False

    def test_empty_signature_header(self) -> None:
        assert verify_webhook_signature(b"body", "", WEBHOOK_SECRET) is False

    def test_missing_sha256_prefix(self) -> None:
        body = b"body"
        raw_digest = hmac.new(
            WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        assert verify_webhook_signature(body, raw_digest, WEBHOOK_SECRET) is False

    def test_tampered_body(self) -> None:
        body = b'{"action": "opened"}'
        sig = sign_payload(body)
        tampered = b'{"action": "closed"}'
        assert verify_webhook_signature(tampered, sig, WEBHOOK_SECRET) is False

    def test_uses_constant_time_comparison(self) -> None:
        """Implementation must use ``hmac.compare_digest``, not ``==``."""
        source = inspect.getsource(verify_webhook_signature)
        assert "compare_digest" in source


# ── Webhook endpoint — signature at HTTP level ────────────────────────────────


class TestWebhookSignature:
    def test_valid_signature_accepted(self, client, mock_service, mock_task) -> None:
        body = json.dumps(make_pr_payload()).encode()
        resp = client.post("/webhooks", content=body, headers=make_headers(body))
        assert resp.status_code == 202

    def test_bad_signature_returns_401(self, client) -> None:
        body = json.dumps(make_pr_payload()).encode()
        headers = make_headers(body, secret="wrong_secret")
        resp = client.post("/webhooks", content=body, headers=headers)
        assert resp.status_code == 401

    def test_missing_signature_returns_401(self, client) -> None:
        body = json.dumps(make_pr_payload()).encode()
        headers = {
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": str(uuid.uuid4()),
            "Content-Type": "application/json",
        }
        resp = client.post("/webhooks", content=body, headers=headers)
        assert resp.status_code == 401


# ── Event filtering (Section 3.1.2) ──────────────────────────────────────────


class TestEventFiltering:
    def test_ping_returns_pong(self, client, mock_service) -> None:
        body = json.dumps({"zen": "Beautiful is better than ugly."}).encode()
        headers = make_headers(body, event="ping")
        resp = client.post("/webhooks", content=body, headers=headers)
        assert resp.status_code == 200
        assert resp.json() == {"status": "pong"}

    def test_unknown_event_returns_200(self, client, mock_service) -> None:
        body = json.dumps({"action": "completed"}).encode()
        headers = make_headers(body, event="check_run")
        resp = client.post("/webhooks", content=body, headers=headers)
        assert resp.status_code == 200

    def test_pr_closed_returns_200(self, client, mock_service) -> None:
        body = json.dumps(make_pr_payload(action="closed")).encode()
        resp = client.post("/webhooks", content=body, headers=make_headers(body))
        assert resp.status_code == 200

    def test_pr_labeled_returns_200(self, client, mock_service) -> None:
        body = json.dumps(make_pr_payload(action="labeled")).encode()
        resp = client.post("/webhooks", content=body, headers=make_headers(body))
        assert resp.status_code == 200

    def test_pr_opened_accepted(self, client, mock_service, mock_task) -> None:
        body = json.dumps(make_pr_payload(action="opened")).encode()
        resp = client.post("/webhooks", content=body, headers=make_headers(body))
        assert resp.status_code == 202

    def test_pr_synchronize_accepted(self, client, mock_service, mock_task) -> None:
        body = json.dumps(make_pr_payload(action="synchronize")).encode()
        resp = client.post("/webhooks", content=body, headers=make_headers(body))
        assert resp.status_code == 202

    def test_pr_reopened_accepted(self, client, mock_service, mock_task) -> None:
        body = json.dumps(make_pr_payload(action="reopened")).encode()
        resp = client.post("/webhooks", content=body, headers=make_headers(body))
        assert resp.status_code == 202


# ── Idempotency (Section 3.1.3) ──────────────────────────────────────────────


class TestIdempotency:
    def test_first_delivery_accepted(
        self, client, fake_redis, mock_service, mock_task
    ) -> None:
        body = json.dumps(make_pr_payload()).encode()
        resp = client.post("/webhooks", content=body, headers=make_headers(body))
        assert resp.status_code == 202

        # Redis key was created
        key = "idempotency:67890:42:" + "a" * 40
        assert fake_redis.get(key) == "1"

    def test_duplicate_delivery_rejected(
        self, client, fake_redis, mock_service, mock_task
    ) -> None:
        body = json.dumps(make_pr_payload()).encode()

        headers1 = make_headers(body)
        assert client.post("/webhooks", content=body, headers=headers1).status_code == 202

        headers2 = make_headers(body)
        assert client.post("/webhooks", content=body, headers=headers2).status_code == 200

    def test_different_shas_not_duplicates(
        self, client, mock_service, mock_task
    ) -> None:
        body1 = json.dumps(make_pr_payload(head_sha="a" * 40)).encode()
        resp1 = client.post("/webhooks", content=body1, headers=make_headers(body1))
        assert resp1.status_code == 202

        body2 = json.dumps(make_pr_payload(head_sha="c" * 40)).encode()
        resp2 = client.post("/webhooks", content=body2, headers=make_headers(body2))
        assert resp2.status_code == 202

    def test_task_not_enqueued_for_duplicate(
        self, client, fake_redis, mock_service, mock_task
    ) -> None:
        body = json.dumps(make_pr_payload()).encode()

        # First → task enqueued
        client.post("/webhooks", content=body, headers=make_headers(body))
        assert mock_task.apply_async.call_count == 1

        # Duplicate → task NOT enqueued again
        client.post("/webhooks", content=body, headers=make_headers(body))
        assert mock_task.apply_async.call_count == 1

    def test_db_level_duplicate_returns_200(
        self, client, mock_service, mock_task
    ) -> None:
        """When Redis misses but DB unique constraint catches the dup."""
        mock_service.create_analysis_run.return_value = None  # DB says duplicate
        body = json.dumps(make_pr_payload()).encode()
        resp = client.post("/webhooks", content=body, headers=make_headers(body))
        assert resp.status_code == 200
        mock_task.apply_async.assert_not_called()


# ── Task enqueue ──────────────────────────────────────────────────────────────


class TestTaskEnqueue:
    def test_enqueued_with_correct_kwargs(
        self, client, mock_service, mock_task
    ) -> None:
        run_id = uuid.uuid4()
        mock_service.upsert_repository.return_value = 1
        mock_service.create_analysis_run.return_value = run_id

        payload = make_pr_payload(
            pr_number=99,
            head_sha="f" * 40,
            base_sha="0" * 40,
            repo_name="org/myrepo",
            installation_id=11111,
            pr_author="alice",
        )
        body = json.dumps(payload).encode()
        client.post("/webhooks", content=body, headers=make_headers(body))

        mock_task.apply_async.assert_called_once()
        call_kw = mock_task.apply_async.call_args.kwargs
        task_kw = call_kw["kwargs"]

        assert task_kw["installation_id"] == 11111
        assert task_kw["repository_full_name"] == "org/myrepo"
        assert task_kw["pull_request_number"] == 99
        assert task_kw["head_sha"] == "f" * 40
        assert task_kw["base_sha"] == "0" * 40
        assert task_kw["pr_author"] == "alice"
        assert task_kw["analysis_run_id"] == str(run_id)
        assert call_kw["queue"] == "cp-high"

    def test_service_functions_called(
        self, client, mock_service, mock_task
    ) -> None:
        """Verify upsert_repository and create_analysis_run are called."""
        body = json.dumps(make_pr_payload()).encode()
        client.post("/webhooks", content=body, headers=make_headers(body))

        mock_service.upsert_repository.assert_called_once()
        mock_service.create_analysis_run.assert_called_once()
        mock_service.log_webhook_event.assert_called()


# ── Webhook event logging ────────────────────────────────────────────────────


class TestWebhookEventLogging:
    def test_ping_logs_processed(self, client, mock_service) -> None:
        body = json.dumps({"zen": "testing"}).encode()
        headers = make_headers(body, event="ping")
        client.post("/webhooks", content=body, headers=headers)

        mock_service.log_webhook_event.assert_called_once()
        call_kw = mock_service.log_webhook_event.call_args
        assert call_kw.kwargs.get("processed") is True or call_kw[1].get("processed") is True

    def test_filtered_event_logged(self, client, mock_service) -> None:
        body = json.dumps({"action": "completed"}).encode()
        headers = make_headers(body, event="check_run")
        client.post("/webhooks", content=body, headers=headers)

        mock_service.log_webhook_event.assert_called_once()

    def test_duplicate_logged_with_flag(
        self, client, fake_redis, mock_service, mock_task
    ) -> None:
        body = json.dumps(make_pr_payload()).encode()
        # First delivery
        client.post("/webhooks", content=body, headers=make_headers(body))
        # Duplicate delivery
        client.post("/webhooks", content=body, headers=make_headers(body))

        # Second call should have duplicate=True
        dup_call = mock_service.log_webhook_event.call_args_list[-1]
        assert dup_call.kwargs.get("duplicate") is True or dup_call[1].get("duplicate") is True


# ── Health endpoints ─────────────────────────────────────────────────────────


class TestHealthEndpoints:
    def test_liveness(self, client) -> None:
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert resp.json()["status"] == "alive"
