"""
Security alert repository (Section 14).

Persists IntrusionSignal objects (Phase 8) as security_alerts rows, and
provides the read/filter/mark-read/mark-resolved operations the Alerts
UI needs.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import select
from sqlalchemy.engine import Engine

from app.core.enums import AuditEventType, AuditSeverity
from app.database.engine import session_scope
from app.database.models import SecurityAlert, USBDevice
from app.detection.signals import IntrusionSignal
from app.logging.audit import write_audit_log
from app.alerts.dto import AlertRecord


def _to_record(alert: SecurityAlert, device_name: Optional[str] = None) -> AlertRecord:
    return AlertRecord(
        id=alert.id, severity=alert.severity, alert_type=alert.alert_type,
        device_id=alert.device_id, device_name=device_name, computer_name=alert.computer_name,
        description=alert.description, is_read=alert.is_read, is_resolved=alert.is_resolved,
        resolved_by=alert.resolved_by, resolved_at=alert.resolved_at, created_at=alert.created_at,
    )


def create_alerts_from_signals(
    signals: list[IntrusionSignal], computer_name: Optional[str] = None, engine: Optional[Engine] = None,
) -> list[AlertRecord]:
    if not signals:
        return []

    records = []
    with session_scope(engine=engine) as session:
        for signal in signals:
            alert = SecurityAlert(
                severity=signal.severity, alert_type=signal.alert_type,
                device_id=signal.device_id, computer_name=computer_name,
                description=signal.description, is_read=False, is_resolved=False,
            )
            session.add(alert)
            session.flush()

            write_audit_log(
                session, AuditEventType.ALERT_GENERATED,
                f"[{signal.severity}] {signal.alert_type}: {signal.description}",
                device_id=signal.device_id, computer_name=computer_name,
                severity=AuditSeverity.CRITICAL if signal.severity == "CRITICAL" else (
                    AuditSeverity.HIGH if signal.severity == "HIGH" else AuditSeverity.WARNING
                ),
            )
            records.append(_to_record(alert))
    return records


def list_alerts(
    severity: Optional[str] = None, alert_type: Optional[str] = None,
    unresolved_only: bool = False, engine: Optional[Engine] = None,
) -> list[AlertRecord]:
    with session_scope(engine=engine) as session:
        stmt = select(SecurityAlert).order_by(SecurityAlert.created_at.desc())
        if severity:
            stmt = stmt.where(SecurityAlert.severity == severity)
        if alert_type:
            stmt = stmt.where(SecurityAlert.alert_type == alert_type)
        if unresolved_only:
            stmt = stmt.where(SecurityAlert.is_resolved == False)  # noqa: E712

        alerts = session.scalars(stmt).all()
        records = []
        for alert in alerts:
            device_name = None
            if alert.device_id:
                device = session.get(USBDevice, alert.device_id)
                device_name = device.name if device else None
            records.append(_to_record(alert, device_name=device_name))
        return records


def mark_read(alert_id: int, engine: Optional[Engine] = None) -> None:
    with session_scope(engine=engine) as session:
        alert = session.get(SecurityAlert, alert_id)
        if alert is None:
            raise ValueError(f"No alert with id={alert_id}")
        alert.is_read = True


def mark_resolved(alert_id: int, resolved_by: int, engine: Optional[Engine] = None) -> AlertRecord:
    with session_scope(engine=engine) as session:
        alert = session.get(SecurityAlert, alert_id)
        if alert is None:
            raise ValueError(f"No alert with id={alert_id}")
        alert.is_resolved = True
        alert.resolved_by = resolved_by
        alert.resolved_at = dt.datetime.utcnow()
        alert.is_read = True
        record = _to_record(alert)
    return record


def get_alert_counts(engine: Optional[Engine] = None) -> dict:
    with session_scope(engine=engine) as session:
        from sqlalchemy import func
        total = session.scalar(select(func.count(SecurityAlert.id))) or 0
        unresolved = session.scalar(
            select(func.count(SecurityAlert.id)).where(SecurityAlert.is_resolved == False)  # noqa: E712
        ) or 0
        return {"total": total, "unresolved": unresolved}
