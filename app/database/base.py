"""
Declarative base for all ORM models.

Kept in its own module (rather than inside engine.py or models.py) so
that both can import it without a circular-import risk as the project
grows across phases.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all database models."""
