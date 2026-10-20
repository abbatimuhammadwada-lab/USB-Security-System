"""
Report data assembly (Section 19): pulls together the three required
report datasets from the repositories already built in earlier phases.
Pure data - no PDF/CSV formatting here, so both exporters (pdf_export.py,
csv_export.py) share exactly the same underlying figures.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.engine import Engine

from app.devices import repository as device_repo
from app.logging.query import search_audit_logs
from app.alerts import repository as alert_repo


@dataclass
class UsbActivityRow:
    timestamp: dt.datetime
    device_name: str
    username: Optional[str]
    action: Optional[str]
    result: Optional[str]


@dataclass
class SecurityIncidentRow:
    timestamp: dt.datetime
    alert_type: str
    severity: str
    device_name: Optional[str]
    description: str
    resolved: bool


@dataclass
class DeviceInventoryData:
    trusted: list
    blocked: list
    unknown: list
    temporary: list


def build_usb_activity_report(
    start: Optional[dt.datetime] = None, end: Optional[dt.datetime] = None, engine: Optional[Engine] = None,
) -> list[UsbActivityRow]:
    logs = search_audit_logs(start=start, end=end, limit=2000, engine=engine)
    rows = []
    for log in logs:
        if log.event_type not in ("USB_CONNECTED", "USB_REMOVED", "ACCESS_ALLOWED", "ACCESS_DENIED"):
            continue
        device_name = "-"
        if log.device_id:
            device = device_repo.get_device(log.device_id, engine=engine)
            device_name = device.display_name() if device else f"Device #{log.device_id}"
        rows.append(UsbActivityRow(
            timestamp=log.timestamp, device_name=device_name, username=log.username,
            action=log.action or log.event_type, result=log.result or "-",
        ))
    return rows


def build_security_incident_report(
    start: Optional[dt.datetime] = None, end: Optional[dt.datetime] = None, engine: Optional[Engine] = None,
) -> list[SecurityIncidentRow]:
    alerts = alert_repo.list_alerts(engine=engine)
    rows = []
    for alert in alerts:
        if start and alert.created_at < start:
            continue
        if end and alert.created_at > end:
            continue
        rows.append(SecurityIncidentRow(
            timestamp=alert.created_at, alert_type=alert.alert_type, severity=alert.severity,
            device_name=alert.device_name, description=alert.description, resolved=alert.is_resolved,
        ))
    return rows


def build_device_inventory_report(engine: Optional[Engine] = None) -> DeviceInventoryData:
    from app.core.enums import DeviceStatus
    return DeviceInventoryData(
        trusted=device_repo.list_devices(status_filter=DeviceStatus.TRUSTED.value, engine=engine),
        blocked=device_repo.list_devices(status_filter=DeviceStatus.BLOCKED.value, engine=engine),
        unknown=device_repo.list_devices(status_filter=DeviceStatus.UNKNOWN.value, engine=engine),
        temporary=device_repo.list_devices(status_filter=DeviceStatus.TEMPORARY.value, engine=engine),
    )
