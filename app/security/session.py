"""
Secure session handling for the desktop application.

This is a single-user-at-a-time desktop app (one Qt process = one logged
in operator), so "session" here means: track who is logged in, when
their session expires from inactivity, and provide one obvious place
for the GUI (Phase 4) to check "am I still logged in?" before allowing
a sensitive action.
"""

from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Session:
    session_token: str
    user_id: int
    username: str
    role: str
    created_at: dt.datetime
    last_activity_at: dt.datetime
    timeout_minutes: int

    def is_expired(self, now: Optional[dt.datetime] = None) -> bool:
        now = now or dt.datetime.utcnow()
        expiry = self.last_activity_at + dt.timedelta(minutes=self.timeout_minutes)
        return now >= expiry

    def touch(self, now: Optional[dt.datetime] = None) -> None:
        """Refresh the session's last-activity timestamp (call on each user action)."""
        self.last_activity_at = now or dt.datetime.utcnow()


class SessionManager:
    """
    Holds at most one active session for this application process.
    Not a general-purpose multi-session/server store - this is a
    single-operator desktop app.
    """

    def __init__(self) -> None:
        self._session: Optional[Session] = None

    def start_session(self, user_id: int, username: str, role: str, timeout_minutes: int) -> Session:
        now = dt.datetime.utcnow()
        self._session = Session(
            session_token=secrets.token_urlsafe(32),
            user_id=user_id,
            username=username,
            role=role,
            created_at=now,
            last_activity_at=now,
            timeout_minutes=timeout_minutes,
        )
        return self._session

    def current(self) -> Optional[Session]:
        if self._session is None:
            return None
        if self._session.is_expired():
            self._session = None
            return None
        return self._session

    def touch(self) -> None:
        if self._session is not None:
            self._session.touch()

    def end_session(self) -> None:
        self._session = None

    def is_authenticated(self) -> bool:
        return self.current() is not None
