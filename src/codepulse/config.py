"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """CodePulse AI configuration.

    All values can be overridden via environment variables.
    """

    # ── Database ────────────────────────────────────────────────────────────────
    database_url: str = "postgresql://codepulse:codepulse_dev@localhost:5432/codepulse"

    # ── Redis ───────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    # Separate Redis DB for app cache/rate-limiting (Section 3.7.2)
    redis_cache_db: int = 1

    # ── GitHub ──────────────────────────────────────────────────────────────────
    github_webhook_secret: str = "dev_webhook_secret_not_for_production"
    github_app_private_key_path: str = "/secrets/github-app-key.pem"
    github_app_id: int = 0  # Set in production

    # ── Gemini / LLM ────────────────────────────────────────────────────────────
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.7-flash"
    gemini_escalation_model: str = "gemini-2.5-pro"

    # ── Mock modes (for local/test without real external APIs) ──────────────────
    mock_github: bool = True
    mock_llm: bool = True

    # ── Celery ──────────────────────────────────────────────────────────────────
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"

    # ── Redis key TTLs (seconds) ────────────────────────────────────────────────
    idempotency_ttl: int = 3600  # 1 hour
    github_token_ttl: int = 3300  # 55 minutes
    file_content_cache_ttl: int = 86400  # 24 hours
    llm_cache_ttl: int = 86400  # 24 hours

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
