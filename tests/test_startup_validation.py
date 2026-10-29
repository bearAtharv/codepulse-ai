"""Unit tests for startup security validation (§3.2, §3.3).

Verifies that the application refuses startup when insecure defaults are used in
live integration mode (MOCK_GITHUB=false or MOCK_LLM=false) or in non-development
environments.
"""

import pytest
from codepulse.config import Settings, validate_settings


def test_startup_refuses_default_webhook_secret_in_live_github():
    """Startup must be rejected if MOCK_GITHUB=false and default webhook secret is used."""
    settings = Settings(
        mock_github=False,
        github_webhook_secret="dev_webhook_secret_not_for_production",
        admin_api_key="a_valid_custom_admin_key_123",
        database_url="postgresql://codepulse:strong_pass@localhost:5432/codepulse",
    )
    with pytest.raises(ValueError, match="default GITHUB_WEBHOOK_SECRET cannot be used"):
        validate_settings(settings)


def test_startup_refuses_default_admin_api_key_in_live_github():
    """Startup must be rejected if MOCK_GITHUB=false and default admin key is used."""
    settings = Settings(
        mock_github=False,
        github_webhook_secret="a_valid_custom_webhook_secret_123",
        admin_api_key="dev_admin_key_not_for_production",
        database_url="postgresql://codepulse:strong_pass@localhost:5432/codepulse",
    )
    with pytest.raises(ValueError, match="default ADMIN_API_KEY cannot be used"):
        validate_settings(settings)


def test_startup_refuses_default_postgres_password_in_live_github():
    """Startup must be rejected if MOCK_GITHUB=false and default postgres password is used."""
    settings = Settings(
        mock_github=False,
        github_webhook_secret="a_valid_custom_webhook_secret_123",
        admin_api_key="a_valid_custom_admin_key_123",
        database_url="postgresql://codepulse:codepulse_dev@localhost:5432/codepulse",
    )
    with pytest.raises(ValueError, match="default hardcoded PostgreSQL password"):
        validate_settings(settings)


def test_startup_refuses_empty_gemini_api_key_in_live_llm():
    """Startup must be rejected if MOCK_LLM=false and GEMINI_API_KEY is empty or placeholder."""
    for bad_key in ("", "   ", "placeholder", "your_gemini_api_key_here"):
        settings = Settings(
            mock_llm=False,
            gemini_api_key=bad_key,
        )
        with pytest.raises(ValueError, match="GEMINI_API_KEY is required and must not be empty"):
            validate_settings(settings)


def test_startup_refuses_defaults_in_production_environment():
    """Startup must be rejected in production even if MOCK_GITHUB=true if defaults remain."""
    settings = Settings(
        environment="production",
        mock_github=True,
        github_webhook_secret="dev_webhook_secret_not_for_production",
        admin_api_key="valid_admin_key",
        database_url="postgresql://codepulse:strong_pass@localhost:5432/codepulse",
    )
    with pytest.raises(ValueError, match="default GITHUB_WEBHOOK_SECRET cannot be used"):
        validate_settings(settings)


def test_startup_succeeds_in_dev_with_mocks():
    """Startup must succeed with dev defaults when MOCK_GITHUB=true and MOCK_LLM=true in development."""
    settings = Settings(
        environment="development",
        mock_github=True,
        mock_llm=True,
        github_webhook_secret="dev_webhook_secret_not_for_production",
        admin_api_key="dev_admin_key_not_for_production",
        database_url="postgresql://codepulse:codepulse_dev@localhost:5432/codepulse",
    )
    # Should not raise
    validate_settings(settings)


def test_startup_succeeds_in_live_mode_with_all_secrets_set():
    """Startup must succeed in live mode when all secrets and keys are provided."""
    settings = Settings(
        environment="production",
        mock_github=False,
        mock_llm=False,
        gemini_api_key="AIzaSy_valid_real_gemini_key",
        github_webhook_secret="prod_webhook_secret_super_secret_456",
        admin_api_key="prod_admin_api_key_789",
        database_url="postgresql://codepulse:super_strong_prod_pass@prod-db:5432/codepulse",
    )
    # Should not raise
    validate_settings(settings)
