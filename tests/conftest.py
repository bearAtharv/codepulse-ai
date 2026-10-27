"""Shared pytest fixtures for CodePulse AI tests."""

import os
import pytest

from codepulse.config import Settings, get_settings


@pytest.fixture(autouse=True, scope="session")
def _isolate_test_redis():
    """Ensure all test runs use Redis database index 15 to isolate from the running stack (DB 0 and DB 1)."""
    current_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
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
    """Clear the lru_cache on get_settings and clear LLM cache before and after every test.

    Prevents stale cached Settings and Redis LLM cache keys from leaking between tests.
    Only deletes keys matching 'llm_cache:*' on isolated test Redis DB 15.
    """
    get_settings.cache_clear()
    try:
        from codepulse.persistence.database import get_redis_client
        client = get_redis_client()
        keys = client.keys("llm_cache:*")
        if keys:
            client.delete(*keys)
    except Exception:
        pass
    yield
    get_settings.cache_clear()
    try:
        from codepulse.persistence.database import get_redis_client
        client = get_redis_client()
        keys = client.keys("llm_cache:*")
        if keys:
            client.delete(*keys)
    except Exception:
        pass


@pytest.fixture()
def settings() -> Settings:
    """Return a test Settings instance with safe defaults."""
    return Settings(
        database_url="postgresql://codepulse:codepulse_dev@localhost:5432/codepulse_test",
        redis_url="redis://localhost:6379/15",
        github_webhook_secret="test_secret",
        mock_github=True,
        mock_llm=True,
    )
