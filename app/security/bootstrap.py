"""
Secure initial administrator creation (Section 7).

There is no hardcoded default administrator account anywhere in this
codebase. The very first administrator must be created explicitly,
either interactively via scripts/create_admin.py (recommended) or via
DEFAULT_ADMIN_USERNAME / DEFAULT_ADMIN_PASSWORD environment variables
for scripted/non-interactive setup (e.g. an automated project-defense
demo environment) - and even then, only if no administrator already
exists, and only if the supplied password passes strength validation.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.engine import Engine

from app.core.enums import UserRole, AuditEventType, AuditSeverity
from app.core.exceptions import ConfigurationError
from app.database.engine import session_scope
from app.database.models import User
from app.logging.audit import write_audit_log
from app.security.password import hash_password, validate_password_strength


@dataclass(frozen=True)
class CreatedAdministrator:
    """Lightweight, detached result of create_initial_administrator() -
    safe to use after the underlying DB session has closed."""
    id: int
    username: str
    role: str


def administrator_exists(engine: Optional[Engine] = None) -> bool:
    with session_scope(engine=engine) as session:
        existing = session.scalar(
            select(User).where(User.role == UserRole.ADMINISTRATOR.value)
        )
        return existing is not None


def create_initial_administrator(
    username: str,
    password: str,
    engine: Optional[Engine] = None,
) -> CreatedAdministrator:
    """
    Create the first administrator account.

    Raises ConfigurationError if:
    - an administrator account already exists (use normal user
      management once the system is bootstrapped, not this function)
    - the username is already taken
    - the password fails strength validation
    """
    username = username.strip()
    if not username:
        raise ConfigurationError("Administrator username must not be empty.")

    if administrator_exists(engine=engine):
        raise ConfigurationError(
            "An administrator account already exists. Use the user "
            "management screen (or a signed-in administrator) to create "
            "additional accounts instead of re-running bootstrap."
        )

    problems = validate_password_strength(password)
    if problems:
        raise ConfigurationError(
            "Password does not meet policy requirements: " + "; ".join(problems)
        )

    with session_scope(engine=engine) as session:
        if session.scalar(select(User).where(User.username == username)) is not None:
            raise ConfigurationError(f"Username '{username}' is already taken.")

        admin = User(
            username=username,
            password_hash=hash_password(password),
            role=UserRole.ADMINISTRATOR.value,
            is_active=True,
            created_at=dt.datetime.utcnow(),
        )
        session.add(admin)
        session.flush()  # populate admin.id before we reference it

        write_audit_log(
            session, AuditEventType.CONFIGURATION_CHANGED,
            f"Initial administrator account '{username}' created via secure bootstrap.",
            user_id=admin.id, result="ALLOWED", severity=AuditSeverity.INFO,
        )

        result = CreatedAdministrator(id=admin.id, username=admin.username, role=admin.role)

    return result
