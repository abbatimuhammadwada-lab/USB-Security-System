"""
Audit log writer (Section 15).

This is the minimal, append-only write path used by every module that
needs to record a security-relevant event (starting with authentication
in Phase 3). Phase 10 adds the read-side: search, filtering, and export
on top of this same table - it does not replace this writer.

By design there is no update_audit_log() or delete_audit_log() function
anywhere in this codebase. Audit rows are inserted once and never
modified through the application.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session as OrmSession

from app.core.enums import AuditEventType, AuditSeverity
from app.database.models import AuditLog


def write_audit_log(
    session: OrmSession,
    event_type: AuditEventType,
    description: str,
    *,
    user_id: Optional[int] = None,
    computer_name: Optional[str] = None,
    device_id: Optional[int] = None,
    action: Optional[str] = None,
    result: Optional[str] = None,
    severity: AuditSeverity = AuditSeverity.INFO,
) -> AuditLog:
    """
    Insert one audit log row using the given (already-open) SQLAlchemy
    session, so the audit record commits atomically with whatever
    business change it documents (e.g. the same transaction that
    updates a user's failed_login_count also writes the FAILED_LOGIN row).

    Does not commit the session itself - the caller's session_scope()
    (or equivalent) controls the transaction boundary.
    """
    entry = AuditLog(
        user_id=user_id,
        computer_name=computer_name,
        event_type=event_type.value,
        device_id=device_id,
        action=action,
        result=result,
        severity=severity.value,
        description=description,
    )
    session.add(entry)
    return entry
