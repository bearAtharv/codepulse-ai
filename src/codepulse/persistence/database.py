"""Database engine and session management.

Engines and session factories are cached per-URL to avoid creating
a new connection pool on every request.
"""

from __future__ import annotations

from typing import Any

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
