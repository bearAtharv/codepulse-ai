"""Declarative base for all SQLAlchemy ORM models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all CodePulse ORM models.

    Alembic reads ``Base.metadata`` for migration autogeneration.
    """

    pass
