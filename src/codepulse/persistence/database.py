"""Database engine and session management.

Engines and session factories are cached per-URL to avoid creating
a new connection pool on every request.
"""

from __future__ import annotations

from typing import Generator
import redis as redis_lib

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from codepulse.config import get_settings

# Module-level caches keyed by database URL
_engines: dict[str, Engine] = {}
_factories: dict[str, sessionmaker[Session]] = {}


def get_engine(database_url: str | None = None) -> Engine:
    """Create or return a cached SQLAlchemy engine.

    Args:
        database_url: Override the URL from settings. Useful for tests.
    """
    url = database_url or get_settings().database_url
    if url not in _engines:
        _engines[url] = create_engine(
            url, pool_pre_ping=True, pool_size=10, max_overflow=20
        )
    return _engines[url]


def get_session_factory(database_url: str | None = None) -> sessionmaker[Session]:
    """Return a cached session factory bound to the engine for the given URL."""
    url = database_url or get_settings().database_url
    if url not in _factories:
        engine = get_engine(url)
        _factories[url] = sessionmaker(bind=engine, expire_on_commit=False)
    return _factories[url]

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
