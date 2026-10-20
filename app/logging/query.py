"""
Audit log search/filter (Section 15, Phase 10 read-side).

The write side (app/logging/audit.py) has existed since Phase 3 -
this module adds the query capability the Audit Logs screen needs:
filter by date range, event type, severity, and user, with pagination.
No update/delete function exists anywhere for audit_logs - this module
is intentionally read-only.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.engine import Engine

from app.database.engine import session_scope
from app.database.models import AuditLog, User


@dataclass(frozen=True)
class AuditLogRecord:
    id: int
    timestamp: dt.datetime
    username: Optional[str]
    computer_name: Optional[str]
    event_type: str
    device_id: Optional[int]
    action: Optional[str]
    result: Optional[str]
    severity: str
    description: str


def search_audit_logs(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    user_id: Optional[int] = None,
    start: Optional[dt.datetime] = None,
    end: Optional[dt.datetime] = None,
    limit: int = 500,
    engine: Optional[Engine] = None,
) -> list[AuditLogRecord]:
    with session_scope(engine=engine) as session:
        stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
        if event_type:
            stmt = stmt.where(AuditLog.event_type == event_type)
        if severity:
            stmt = stmt.where(AuditLog.severity == severity)
        if user_id:
            stmt = stmt.where(AuditLog.user_id == user_id)
        if start:
            stmt = stmt.where(AuditLog.timestamp >= start)
        if end:
            stmt = stmt.where(AuditLog.timestamp <= end)

        rows = session.scalars(stmt).all()
        records = []
        for row in rows:
            username = None
            if row.user_id:
                user = session.get(User, row.user_id)
                username = user.username if user else None
            records.append(AuditLogRecord(
                id=row.id, timestamp=row.timestamp, username=username,
                computer_name=row.computer_name, event_type=row.event_type,
                device_id=row.device_id, action=row.action, result=row.result,
                severity=row.severity, description=row.description,
            ))
        return records


def distinct_event_types(engine: Optional[Engine] = None) -> list[str]:
    with session_scope(engine=engine) as session:
        rows = session.scalars(select(AuditLog.event_type).distinct().order_by(AuditLog.event_type)).all()
        return list(rows)
