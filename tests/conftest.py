"""Shared pytest fixtures for CodePulse AI tests."""

import pytest

from codepulse.config import Settings


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
