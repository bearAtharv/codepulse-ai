"""Shared pytest fixtures for CodePulse AI tests."""

import os
import pytest

# Ensure pytest runs in deterministic mock/development environment even if a local .env exists
os.environ["TEST_ENV"] = "true"
os.environ["ENVIRONMENT"] = "development"
os.environ["MOCK_GITHUB"] = "true"
os.environ["MOCK_LLM"] = "true"
os.environ["MOCK_LLM_FAILURE"] = "false"
os.environ["MOCK_RATE_LIMIT"] = "false"
os.environ["MOCK_GITHUB_RATE_LIMIT"] = "false"
os.environ["MOCK_POSTING_FAILURE"] = "false"
os.environ["MOCK_QUICK_RETRIES"] = "false"
os.environ["GITHUB_WEBHOOK_SECRET"] = "dev_webhook_secret_not_for_production"
os.environ["ADMIN_API_KEY"] = "dev_admin_key_not_for_production"

from codepulse.config import Settings, get_settings


@pytest.fixture(autouse=True, scope="session")
def _isolate_test_redis():
    """Ensure all test runs use Redis database index 15 to isolate from the running stack (DB 0 and DB 1)."""
    current_url = os.environ.get("REDIS_URL") or get_settings().redis_url
    if "/" in current_url.split("://")[-1]:
        test_url = f"{current_url.rsplit('/', 1)[0]}/15"
    else:
        test_url = f"{current_url}/15"
    os.environ["REDIS_URL"] = test_url
    get_settings.cache_clear()
    import codepulse.persistence.database as db_mod
    db_mod._redis_client = None

    # Flush DB 15 before session starts
    try:
        client = db_mod.get_redis_client()
        client.flushdb()
    except Exception:
        pass

    yield

    # Clean up DB 15 after session finishes
    try:
        client = db_mod.get_redis_client()
        client.flushdb()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Clear the lru_cache on get_settings and clear LLM cache/circuit breaker before and after every test.

    Prevents stale cached Settings and Redis keys from leaking between tests.
    Only deletes keys matching 'llm_cache:*' and 'circuit:*' on isolated test Redis DB 15.
    """
    get_settings.cache_clear()
    try:
        from codepulse.persistence.database import get_redis_client
        client = get_redis_client()
        keys = client.keys("llm_cache:*") + client.keys("circuit:*")
        if keys:
            client.delete(*keys)
    except Exception:
        pass
    yield
    get_settings.cache_clear()
    try:
        from codepulse.persistence.database import get_redis_client
        client = get_redis_client()
        keys = client.keys("llm_cache:*") + client.keys("circuit:*")
        if keys:
            client.delete(*keys)
    except Exception:
        pass


@pytest.fixture()
def settings() -> Settings:
    """Return a test Settings instance with safe defaults."""
    test_redis_url = os.environ.get("REDIS_URL") or "redis://localhost:6379/15"
    return Settings(
        database_url="postgresql://codepulse:codepulse_dev@localhost:5432/codepulse_test",
        redis_url=test_redis_url,
        github_webhook_secret="test_secret",
        mock_github=True,
        mock_llm=True,
    )
