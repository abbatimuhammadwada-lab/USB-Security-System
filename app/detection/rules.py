"""
Rule-based USB intrusion detection (Section 13).

These are plain, readable heuristics over data already being recorded
by earlier phases (device_events, audit_logs, system_settings) - NOT
machine learning, and the system must never claim otherwise (Rule 13 /
Section 13: "Do NOT claim that these heuristics are advanced AI or
machine learning. Clearly describe them as rule-based intrusion
detection.").

Each check returns an IntrusionSignal, or None if the pattern did not
occur. A single connection event can legitimately trigger more than one
signal at once (e.g. a blacklisted device connecting outside business
hours is both BLACKLISTED_USB and AFTER_HOURS_CONNECTION).
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.engine import Engine

from app.config.settings import settings
from app.core.enums import AlertType, AlertSeverity, DeviceStatus, EnforcementResult
from app.database.engine import session_scope
from app.database.models import DeviceEvent, SystemSetting
from app.detection.signals import IntrusionSignal
from app.devices.dto import DeviceRecord
from app.policy.engine import PolicyDecision

_UNAUTHORIZED_RESULTS = {
    EnforcementResult.UNAUTHORIZED.value,
    EnforcementResult.BLOCKED.value,
    EnforcementResult.BLOCKING_FAILED.value,
}


def check_unknown_device(device: DeviceRecord) -> Optional[IntrusionSignal]:
    if device.status == DeviceStatus.UNKNOWN.value:
        return IntrusionSignal(
            AlertType.UNKNOWN_USB.value, AlertSeverity.MEDIUM.value,
            f"Device '{device.display_name()}' has never been approved by an administrator.",
            device_id=device.id,
        )
    return None


def check_blacklisted_device(device: DeviceRecord) -> Optional[IntrusionSignal]:
    if device.status == DeviceStatus.BLOCKED.value:
        return IntrusionSignal(
            AlertType.BLACKLISTED_USB.value, AlertSeverity.HIGH.value,
            f"Blocked/blacklisted device '{device.display_name()}' attempted to connect.",
            device_id=device.id,
        )
    return None


def check_policy_violation(device: DeviceRecord, decision: Optional[PolicyDecision]) -> Optional[IntrusionSignal]:
    if decision is not None and decision.action == "BLOCK":
        return IntrusionSignal(
            AlertType.POLICY_VIOLATION.value, AlertSeverity.HIGH.value,
            f"Connection of '{device.display_name()}' denied by policy: {decision.reason}",
            device_id=device.id,
        )
    return None


def check_repeated_unauthorized_attempts(
    device_id: int, engine: Optional[Engine] = None,
    threshold: Optional[int] = None, window_minutes: Optional[int] = None,
    now: Optional[dt.datetime] = None,
) -> Optional[IntrusionSignal]:
    threshold = threshold if threshold is not None else settings.unauthorized_attempt_threshold
    window_minutes = window_minutes if window_minutes is not None else settings.unauthorized_attempt_window_minutes
    now = now or dt.datetime.utcnow()
    window_start = now - dt.timedelta(minutes=window_minutes)

    with session_scope(engine=engine) as session:
        count = session.scalar(
            select(func.count(DeviceEvent.id)).where(
                DeviceEvent.device_id == device_id,
                DeviceEvent.result.in_(_UNAUTHORIZED_RESULTS),
                DeviceEvent.timestamp >= window_start,
            )
        ) or 0

    if count >= threshold:
        return IntrusionSignal(
            AlertType.REPEATED_UNAUTHORIZED_ATTEMPTS.value, AlertSeverity.HIGH.value,
            f"{count} unauthorized connection attempts for this device within "
            f"the last {window_minutes} minute(s) (threshold: {threshold}).",
            device_id=device_id,
        )
    return None


def check_rapid_connect_disconnect(
    device_id: int, engine: Optional[Engine] = None,
    window_seconds: int = 60, cycle_threshold: int = 3,
    now: Optional[dt.datetime] = None,
) -> Optional[IntrusionSignal]:
    now = now or dt.datetime.utcnow()
    window_start = now - dt.timedelta(seconds=window_seconds)

    with session_scope(engine=engine) as session:
        count = session.scalar(
            select(func.count(DeviceEvent.id)).where(
                DeviceEvent.device_id == device_id,
                DeviceEvent.event_type == "CONNECTED",
                DeviceEvent.timestamp >= window_start,
            )
        ) or 0

    if count >= cycle_threshold:
        return IntrusionSignal(
            AlertType.RAPID_CONNECT_DISCONNECT.value, AlertSeverity.MEDIUM.value,
            f"Device connected {count} times within the last {window_seconds} seconds "
            f"(threshold: {cycle_threshold}) - possible tampering or faulty connection.",
            device_id=device_id,
        )
    return None


def _get_system_setting(session, key: str, default: str) -> str:
    row = session.scalar(select(SystemSetting).where(SystemSetting.key == key))
    return row.value if row and row.value else default


def check_after_hours(
    device: DeviceRecord, event_timestamp: dt.datetime, engine: Optional[Engine] = None,
) -> Optional[IntrusionSignal]:
    with session_scope(engine=engine) as session:
        start_str = _get_system_setting(session, "business_hours_start", "08:00")
        end_str = _get_system_setting(session, "business_hours_end", "18:00")

    try:
        start_h, start_m = (int(p) for p in start_str.split(":"))
        end_h, end_m = (int(p) for p in end_str.split(":"))
    except (ValueError, AttributeError):
        return None  # misconfigured business hours - skip rather than crash (Section 20)

    start = dt.time(start_h, start_m)
    end = dt.time(end_h, end_m)
    current = event_timestamp.time()

    in_hours = start <= current <= end if start <= end else (current >= start or current <= end)
    if in_hours:
        return None

    return IntrusionSignal(
        AlertType.AFTER_HOURS_CONNECTION.value, AlertSeverity.MEDIUM.value,
        f"Device '{device.display_name()}' connected outside configured business hours "
        f"({start_str}-{end_str}) at {event_timestamp.strftime('%H:%M')} UTC.",
        device_id=device.id,
    )
