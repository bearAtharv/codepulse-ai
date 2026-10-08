"""Shared pytest fixtures for CodePulse AI tests."""

import pytest

from codepulse.config import Settings, get_settings


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Clear the lru_cache on get_settings before and after every test.

    Prevents stale cached Settings from leaking between tests when
    environment variables are patched.
    """
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


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
