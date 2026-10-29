"""Application configuration loaded from environment variables."""

from functools import lru_cache

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

    # ── Environment & Admin ─────────────────────────────────────────────────────
    environment: str = "development"
    admin_api_key: str | None = None

    # ── Mock modes (for local/test without real external APIs) ──────────────────
    mock_github: bool = True
    mock_llm: bool = True
    mock_diff_fetch_failure: bool = False
    mock_posting_failure: bool = False
    mock_persist_failure: bool = False

    # ── Celery ──────────────────────────────────────────────────────────────────
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"

    # ── Redis key TTLs (seconds) ────────────────────────────────────────────────
    idempotency_ttl: int = 3600  # 1 hour
    github_token_ttl: int = 3300  # 55 minutes
    file_content_cache_ttl: int = 86400  # 24 hours
    llm_cache_ttl: int = 86400  # 24 hours
    diff_cache_ttl: int = 86400  # 24 hours
    review_payload_cache_ttl: int = 86400  # 24 hours

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance (re-uses across calls)."""
    return Settings()


def validate_settings(settings: Settings) -> None:
    """Validate startup security configurations (§3.2, §3.3).

    Refuses to start if insecure defaults are used when live integration is enabled
    (MOCK_GITHUB=false or MOCK_LLM=false) or in non-development environments.
    """
    is_live_github = not settings.mock_github
    is_non_dev = settings.environment.lower() != "development"

    if is_live_github or is_non_dev:
        if settings.github_webhook_secret == "dev_webhook_secret_not_for_production":
            raise ValueError(
                "Refusing to start: default GITHUB_WEBHOOK_SECRET cannot be used "
                "when MOCK_GITHUB=false or ENVIRONMENT != development."
            )
        if settings.admin_api_key == "dev_admin_key_not_for_production":
            raise ValueError(
                "Refusing to start: default ADMIN_API_KEY cannot be used "
                "when MOCK_GITHUB=false or ENVIRONMENT != development."
            )
        if ":codepulse_dev@" in settings.database_url:
            raise ValueError(
                "Refusing to start: default hardcoded PostgreSQL password ('codepulse_dev') "
                "cannot be used when MOCK_GITHUB=false or ENVIRONMENT != development."
            )

    if not settings.mock_llm:
        if not settings.gemini_api_key or settings.gemini_api_key.strip() in ("", "placeholder", "your_gemini_api_key_here"):
            raise ValueError(
                "Refusing to start: GEMINI_API_KEY is required and must not be empty when MOCK_LLM=false."
            )

