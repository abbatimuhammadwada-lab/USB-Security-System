"""
Authentication service (Section 7).

Handles login validation, password verification, failed-login tracking
with account lockout, session creation, and logout - with every outcome
(success or failure) written to the audit log in the same transaction
as any state change (e.g. incrementing failed_login_count).

Generic error messages are used for "unknown username" and "wrong
password" so the caller cannot distinguish the two (prevents username
enumeration). Locked/disabled account states give more specific
messages since these accounts are administrator-managed, not public
self-service accounts, so operational clarity outweighs the (low)
enumeration risk for this desktop application.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.engine import Engine

from app.config.settings import settings
from app.core.enums import AuditEventType, AuditSeverity
from app.core.exceptions import AuthenticationError
from app.database.engine import session_scope
from app.database.models import User
from app.logging.audit import write_audit_log
from app.security.password import verify_password, needs_rehash, hash_password
from app.security.session import SessionManager, Session


@dataclass(frozen=True)
class AuthenticatedUser:
    """Lightweight, detached representation of the logged-in user -
    returned instead of the ORM object, which becomes invalid once its
    session_scope() closes."""
    id: int
    username: str
    role: str


class AuthService:
    def __init__(
        self,
        engine: Optional[Engine] = None,
        max_failed_logins: Optional[int] = None,
        lockout_minutes: Optional[int] = None,
        session_timeout_minutes: Optional[int] = None,
    ) -> None:
        self._engine = engine
        self._max_failed_logins = max_failed_logins if max_failed_logins is not None else settings.max_failed_logins
        self._lockout_minutes = lockout_minutes if lockout_minutes is not None else settings.lockout_minutes
        self._session_timeout_minutes = (
            session_timeout_minutes if session_timeout_minutes is not None else settings.session_timeout_minutes
        )
        self.session_manager = SessionManager()

    def authenticate(self, username: str, password: str, computer_name: Optional[str] = None) -> AuthenticatedUser:
        """
        Validate credentials and start a session on success.

        Implementation note: every failure branch below must still COMMIT
        its audit log entry (and, for wrong passwords, the incremented
        failed_login_count / lockout). session_scope() rolls back the
        transaction if any exception escapes the `with` block, so the
        AuthenticationError for a rejected login is deliberately raised
        AFTER the `with` block exits (and therefore after the commit),
        never from inside it - otherwise the failed-attempt record would
        be discarded along with the "failure", which would silently
        defeat the lockout mechanism.
        """
        computer_name = computer_name or settings.computer_name
        now = dt.datetime.utcnow()
        failure: Optional[AuthenticationError] = None
        authenticated: Optional[AuthenticatedUser] = None

        with session_scope(engine=self._engine) as session:
            user = session.scalar(select(User).where(User.username == username))

            if user is None:
                write_audit_log(
                    session, AuditEventType.FAILED_LOGIN,
                    f"Login attempt for unknown username '{username}'.",
                    computer_name=computer_name, result="UNAUTHORIZED", severity=AuditSeverity.WARNING,
                )
                failure = AuthenticationError("Invalid username or password.")

            elif not user.is_active:
                write_audit_log(
                    session, AuditEventType.FAILED_LOGIN,
                    f"Login attempt for disabled account '{username}'.",
                    user_id=user.id, computer_name=computer_name,
                    result="UNAUTHORIZED", severity=AuditSeverity.WARNING,
                )
                failure = AuthenticationError("This account has been disabled. Contact an administrator.")

            elif user.locked_until is not None and user.locked_until > now:
                write_audit_log(
                    session, AuditEventType.FAILED_LOGIN,
                    f"Login attempt for locked account '{username}' (locked until {user.locked_until.isoformat()} UTC).",
                    user_id=user.id, computer_name=computer_name,
                    result="UNAUTHORIZED", severity=AuditSeverity.WARNING,
                )
                failure = AuthenticationError(
                    f"Account is locked until {user.locked_until.isoformat()} UTC due to repeated failed login attempts."
                )

            elif not verify_password(password, user.password_hash):
                user.failed_login_count += 1
                just_locked = False
                if user.failed_login_count >= self._max_failed_logins:
                    user.locked_until = now + dt.timedelta(minutes=self._lockout_minutes)
                    just_locked = True

                write_audit_log(
                    session, AuditEventType.FAILED_LOGIN,
                    f"Incorrect password for '{username}' "
                    f"(attempt {user.failed_login_count}/{self._max_failed_logins}).",
                    user_id=user.id, computer_name=computer_name,
                    result="UNAUTHORIZED",
                    severity=AuditSeverity.HIGH if just_locked else AuditSeverity.WARNING,
                )

                if just_locked:
                    failure = AuthenticationError(
                        f"Account locked for {self._lockout_minutes} minutes after "
                        f"{self._max_failed_logins} failed login attempts."
                    )
                else:
                    failure = AuthenticationError("Invalid username or password.")

            else:
                # --- success ---
                user.failed_login_count = 0
                user.locked_until = None
                user.last_login_at = now
                if needs_rehash(user.password_hash):
                    user.password_hash = hash_password(password)

                write_audit_log(
                    session, AuditEventType.LOGIN,
                    f"User '{username}' logged in.",
                    user_id=user.id, computer_name=computer_name,
                    result="ALLOWED", severity=AuditSeverity.INFO,
                )
                authenticated = AuthenticatedUser(id=user.id, username=user.username, role=user.role)

        # `with` block has exited -> commit has already happened.
        if failure is not None:
            raise failure

        assert authenticated is not None  # for type checkers; guaranteed by the branches above
        self.session_manager.start_session(
            authenticated.id, authenticated.username, authenticated.role, self._session_timeout_minutes
        )
        return authenticated

    def logout(self, computer_name: Optional[str] = None) -> None:
        current = self.session_manager.current()
        if current is None:
            return
        with session_scope(engine=self._engine) as session:
            write_audit_log(
                session, AuditEventType.LOGOUT,
                f"User '{current.username}' logged out.",
                user_id=current.user_id,
                computer_name=computer_name or settings.computer_name,
                result="ALLOWED", severity=AuditSeverity.INFO,
            )
        self.session_manager.end_session()

    def current_session(self) -> Optional[Session]:
        return self.session_manager.current()

    def is_authenticated(self) -> bool:
        return self.session_manager.is_authenticated()
