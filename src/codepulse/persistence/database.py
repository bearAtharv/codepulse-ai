"""Database engine and session management."""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from codepulse.config import get_settings


def get_engine(database_url: str | None = None):
    """Create a SQLAlchemy engine.

    Args:
        database_url: Override the URL from settings. Useful for tests.
    """
    url = database_url or get_settings().database_url
    return create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20)


def get_session_factory(database_url: str | None = None) -> sessionmaker[Session]:
    """Return a session factory bound to the default engine."""
    engine = get_engine(database_url)
    return sessionmaker(bind=engine, expire_on_commit=False)
