"""FastAPI dependency-injection providers for Redis, DB sessions, and Settings."""

from __future__ import annotations

from typing import Generator

import redis as redis_lib
from sqlalchemy.orm import Session

from codepulse.config import Settings, get_settings
from codepulse.persistence.database import get_session_factory

# Module-level singleton; overridden in tests via FastAPI dependency_overrides.
_redis_client: redis_lib.Redis | None = None


def get_redis_client() -> redis_lib.Redis:
    """Return a shared Redis client (connection-pooled internally by redis-py)."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = redis_lib.Redis.from_url(
            settings.redis_url, decode_responses=True
        )
    return _redis_client


def get_db_session() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy session, ensuring it is closed after use."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()


def get_settings_dep() -> Settings:
    """Return application settings (injectable FastAPI dependency)."""
    return get_settings()
