"""Shared pytest fixtures for CodePulse AI tests."""

import pytest

from codepulse.config import Settings, get_settings


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Clear the lru_cache on get_settings and clear LLM cache before and after every test.

    Prevents stale cached Settings and Redis LLM cache keys from leaking between tests.
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
        redis_url="redis://localhost:6379/1",
        github_webhook_secret="test_secret",
        mock_github=True,
        mock_llm=True,
    )
