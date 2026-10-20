"""
Database engine and session management.

Provides a single SQLAlchemy engine for the application's configured
DATABASE_URL, a session factory, and a context-managed session helper
that commits on success and rolls back on any exception - so calling
code never has to remember to do it manually (Section 20: no partial
writes left dangling on failure).

SQLite specifics handled here:
- Foreign key enforcement is OFF by default in SQLite; we turn it on
  per-connection via an event listener (Section 18 requires enforced
  foreign keys).
- `check_same_thread=False` is set because the USB monitoring thread
  (Phase 5) and the Qt GUI thread (Phase 4) both need DB access; each
  unit of work still gets its own short-lived Session, so this is safe.
"""

from __future__ import annotations

import contextlib
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker, Session

from app.config.settings import settings
from app.core.exceptions import DatabaseError

_engine: Engine | None = None
_SessionFactory: sessionmaker | None = None


def _build_engine(database_url: str) -> Engine:
    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    try:
        engine = create_engine(database_url, connect_args=connect_args, future=True)
    except Exception as exc:  # pragma: no cover - defensive
        raise DatabaseError(f"Failed to create database engine: {exc}") from exc

    if database_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, connection_record):  # noqa: ANN001
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def get_engine(database_url: str | None = None) -> Engine:
    """
    Return the process-wide engine (creating it on first use), unless an
    explicit database_url is given - in which case a fresh, independent
    engine is built and returned without touching the cached global
    engine. This lets tests build an isolated in-memory/temp-file engine
    without disturbing the real application's singleton.
    """
    if database_url is not None:
        return _build_engine(database_url)

    global _engine
    if _engine is None:
        _engine = _build_engine(settings.database_url)
    return _engine


def get_session_factory(engine: Engine | None = None) -> sessionmaker:
    """Return a session factory bound to the given engine, or the cached
    global session factory (bound to the global engine) if none is given."""
    if engine is not None:
        return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            bind=get_engine(), autoflush=False, autocommit=False, future=True
        )
    return _SessionFactory


@contextlib.contextmanager
def session_scope(engine: Engine | None = None) -> Generator[Session, None, None]:
    """
    Provide a transactional scope around a series of operations.

    Usage:
        with session_scope() as session:
            session.add(obj)

    Pass an explicit `engine` (e.g. from get_engine(database_url=...)) to
    operate against a non-default database, such as an isolated test DB.

    On any exception, the transaction is rolled back. Only genuine
    SQLAlchemy errors are re-wrapped as DatabaseError; application-level
    exceptions raised inside the `with` block (ValueError for "not
    found", the app's own USBSecuritySystemError subclasses, etc.)
    propagate unchanged after the rollback, so callers can catch the
    specific error they raised instead of a generic DatabaseError.
    """
    session = get_session_factory(engine=engine)()
    try:
        yield session
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise DatabaseError(f"Database transaction failed and was rolled back: {exc}") from exc
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_global_engine_cache() -> None:
    """
    Clear the cached global engine/session factory. Intended for tests
    that need a fresh engine bound to a new settings.database_url within
    the same process. Not used during normal application execution.
    """
    global _engine, _SessionFactory
    _engine = None
    _SessionFactory = None
