"""
Device registry repository (Section 11).

This is where a detected USB event (Phase 5's USBDeviceInfo) becomes a
persistent registry entry: get-or-create the device_fingerprints row,
get-or-create the usb_devices row, record the device_events row, and
write the corresponding audit log entry.

Scope boundary (deliberate): this module does NOT decide whether a
device's connection should be allowed or blocked - that is the policy
engine's job (Phase 7) and enforcement's job (Phase 7/8, app/enforcement).
A freshly detected device is simply recorded with
DeviceEvent.result = DETECTED (or REMOVED on disconnect); its
usb_devices.status (TRUSTED/BLOCKED/UNKNOWN/TEMPORARY) only changes
through the explicit approve/block/revoke actions below, which an
administrator performs deliberately - never automatically from a
connection event.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.engine import Engine

from app.core.enums import (
    DeviceStatus, DeviceEventType, EnforcementResult,
    AuditEventType, AuditSeverity,
)
from app.core.exceptions import DeviceFingerprintError
from app.database.engine import session_scope
from app.database.models import DeviceFingerprint, USBDevice, DeviceEvent
from app.devices.dto import DeviceRecord, DeviceEventRecord, DeviceCounts
from app.logging.audit import write_audit_log
from app.usb.classifier import classify_device
from app.usb.device_info import USBDeviceInfo
from app.usb.fingerprint import compute_fingerprint

logger = logging.getLogger(__name__)


def _to_device_record(device: USBDevice) -> DeviceRecord:
    return DeviceRecord(
        id=device.id, fingerprint_id=device.fingerprint_id, name=device.name,
        manufacturer=device.manufacturer, vendor_id=device.vendor_id,
        product_id=device.product_id, serial_number=device.serial_number,
        pnp_device_id=device.pnp_device_id, device_class=device.device_class,
        device_type=device.device_type, status=device.status,
        first_seen=device.first_seen, last_seen=device.last_seen,
        connection_count=device.connection_count, approved_by=device.approved_by,
        approved_at=device.approved_at, temporary_expires_at=device.temporary_expires_at,
    )


def _to_event_record(event: DeviceEvent) -> DeviceEventRecord:
    return DeviceEventRecord(
        id=event.id, device_id=event.device_id, event_type=event.event_type,
        result=event.result, is_simulated=event.is_simulated, user_id=event.user_id,
        computer_name=event.computer_name, drive_letter=event.drive_letter,
        timestamp=event.timestamp,
    )


def _expire_temporary_authorization_if_needed(device: USBDevice, now: dt.datetime) -> bool:
    """If a TEMPORARY device's authorization window has passed, revert it
    to UNKNOWN. Returns True if a change was made (caller should audit-log it)."""
    if device.status == DeviceStatus.TEMPORARY.value and device.temporary_expires_at is not None:
        if device.temporary_expires_at <= now:
            device.status = DeviceStatus.UNKNOWN.value
            device.temporary_expires_at = None
            return True
    return False


def record_device_event(info: USBDeviceInfo, engine: Optional[Engine] = None) -> Optional[DeviceEventRecord]:
    """
    Persist a detected USB connect/remove event into the registry.

    Returns None (and writes an explanatory audit log entry) if the
    device could not be fingerprinted at all - this is a handled,
    expected outcome (Section 20: never crash on missing USB info),
    not an exception the caller needs to catch.
    """
    now = dt.datetime.utcnow()

    try:
        fingerprint = compute_fingerprint(info)
    except DeviceFingerprintError as exc:
        with session_scope(engine=engine) as session:
            write_audit_log(
                session,
                AuditEventType.USB_CONNECTED if info.is_connect() else AuditEventType.USB_REMOVED,
                f"USB {info.event_type.lower()} event received but could not be fingerprinted: {exc}",
                computer_name=info.computer_name, result="UNKNOWN", severity=AuditSeverity.WARNING,
            )
        logger.warning(f"Could not fingerprint device event: {exc}")
        return None

    with session_scope(engine=engine) as session:
        fp_row = session.scalar(
            select(DeviceFingerprint).where(DeviceFingerprint.fingerprint_hash == fingerprint.fingerprint_hash)
        )
        if fp_row is None:
            fp_row = DeviceFingerprint(
                vendor_id=fingerprint.vendor_id, product_id=fingerprint.product_id,
                serial_number=fingerprint.serial_number, pnp_device_id=fingerprint.pnp_device_id,
                manufacturer=fingerprint.manufacturer, device_class=fingerprint.device_class,
                fingerprint_hash=fingerprint.fingerprint_hash,
            )
            session.add(fp_row)
            session.flush()

        device = session.scalar(select(USBDevice).where(USBDevice.fingerprint_id == fp_row.id))
        device_class = classify_device(info)

        if device is None:
            device = USBDevice(
                fingerprint_id=fp_row.id,
                name=info.name, manufacturer=info.manufacturer,
                vendor_id=info.vendor_id, product_id=info.product_id,
                serial_number=info.serial_number, pnp_device_id=info.pnp_device_id,
                device_class=device_class.value, device_type=device_class.value,
                status=DeviceStatus.UNKNOWN.value,
                first_seen=now, last_seen=now, connection_count=0,
            )
            session.add(device)
            session.flush()
        else:
            # Fill in any fields that were previously unknown, without
            # overwriting good existing data with a sparser later reading.
            device.name = device.name or info.name
            device.manufacturer = device.manufacturer or info.manufacturer
            device.pnp_device_id = device.pnp_device_id or info.pnp_device_id

        expired = _expire_temporary_authorization_if_needed(device, now)
        if expired:
            write_audit_log(
                session, AuditEventType.DEVICE_REVOKED,
                f"Temporary authorization for '{device.name or f'device #{device.id}'}' expired automatically.",
                device_id=device.id, result="UNKNOWN", severity=AuditSeverity.INFO,
            )

        if info.is_connect():
            device.last_seen = now
            device.connection_count += 1
            result = EnforcementResult.DETECTED.value
            audit_event_type = AuditEventType.USB_CONNECTED
        else:
            device.last_seen = now
            result = EnforcementResult.REMOVED.value
            audit_event_type = AuditEventType.USB_REMOVED

        event = DeviceEvent(
            device_id=device.id,
            event_type=info.event_type,
            result=result,
            is_simulated=info.is_simulated,
            computer_name=info.computer_name,
            drive_letter=info.drive_letter,
            timestamp=info.timestamp,
            raw_metadata=info.as_metadata_json(),
        )
        session.add(event)
        session.flush()

        write_audit_log(
            session, audit_event_type,
            f"USB device '{info.display_name()}' {info.event_type.lower()} "
            f"(status={device.status}, simulated={info.is_simulated}).",
            device_id=device.id, computer_name=info.computer_name,
            result=result, severity=AuditSeverity.INFO,
        )

        record = _to_event_record(event)

    return record


def update_event_result(event_id: int, result: str, engine: Optional[Engine] = None) -> None:
    """Update a previously-recorded DeviceEvent's result once policy
    evaluation (and, for BLOCK decisions, enforcement) has run. Called
    by app.policy.pipeline after record_device_event() has already
    persisted the initial DETECTED/REMOVED row."""
    with session_scope(engine=engine) as session:
        event = session.get(DeviceEvent, event_id)
        if event is None:
            raise ValueError(f"No device event with id={event_id}")
        event.result = result


# --- Administrator actions (Section 11) -------------------------------------------------
def approve_device(device_id: int, approved_by_user_id: int, engine: Optional[Engine] = None) -> DeviceRecord:
    now = dt.datetime.utcnow()
    with session_scope(engine=engine) as session:
        device = session.get(USBDevice, device_id)
        if device is None:
            raise ValueError(f"No device with id={device_id}")

        device.status = DeviceStatus.TRUSTED.value
        device.approved_by = approved_by_user_id
        device.approved_at = now
        device.temporary_expires_at = None

        write_audit_log(
            session, AuditEventType.DEVICE_APPROVED,
            f"Device '{device.name or device.id}' approved as trusted.",
            device_id=device.id, user_id=approved_by_user_id,
            result="ALLOWED", severity=AuditSeverity.INFO,
        )
        record = _to_device_record(device)
    return record


def authorize_temporary(
    device_id: int, approved_by_user_id: int, expires_at: dt.datetime, engine: Optional[Engine] = None
) -> DeviceRecord:
    now = dt.datetime.utcnow()
    if expires_at <= now:
        raise ValueError("Temporary authorization expiry must be in the future.")

    with session_scope(engine=engine) as session:
        device = session.get(USBDevice, device_id)
        if device is None:
            raise ValueError(f"No device with id={device_id}")

        device.status = DeviceStatus.TEMPORARY.value
        device.approved_by = approved_by_user_id
        device.approved_at = now
        device.temporary_expires_at = expires_at

        write_audit_log(
            session, AuditEventType.DEVICE_APPROVED,
            f"Device '{device.name or device.id}' temporarily authorized until {expires_at.isoformat()} UTC.",
            device_id=device.id, user_id=approved_by_user_id,
            result="ALLOWED", severity=AuditSeverity.INFO,
        )
        record = _to_device_record(device)
    return record


def block_device(device_id: int, blocked_by_user_id: int, engine: Optional[Engine] = None) -> DeviceRecord:
    with session_scope(engine=engine) as session:
        device = session.get(USBDevice, device_id)
        if device is None:
            raise ValueError(f"No device with id={device_id}")

        device.status = DeviceStatus.BLOCKED.value
        device.temporary_expires_at = None

        write_audit_log(
            session, AuditEventType.DEVICE_BLOCKED,
            f"Device '{device.name or device.id}' added to the blocked-device registry. "
            f"(Registry status only - active enforcement against a currently connected "
            f"instance of this device happens through the enforcement layer, not here.)",
            device_id=device.id, user_id=blocked_by_user_id,
            result="BLOCKED", severity=AuditSeverity.HIGH,
        )
        record = _to_device_record(device)
    return record


def revoke_device(device_id: int, revoked_by_user_id: int, engine: Optional[Engine] = None) -> DeviceRecord:
    """Return a device to UNKNOWN status, clearing any trust/block/temporary state."""
    with session_scope(engine=engine) as session:
        device = session.get(USBDevice, device_id)
        if device is None:
            raise ValueError(f"No device with id={device_id}")

        device.status = DeviceStatus.UNKNOWN.value
        device.approved_by = None
        device.approved_at = None
        device.temporary_expires_at = None

        write_audit_log(
            session, AuditEventType.DEVICE_REVOKED,
            f"Device '{device.name or device.id}' authorization revoked; status reset to UNKNOWN.",
            device_id=device.id, user_id=revoked_by_user_id,
            result="UNKNOWN", severity=AuditSeverity.WARNING,
        )
        record = _to_device_record(device)
    return record


# --- Queries -------------------------------------------------
def list_devices(status_filter: Optional[str] = None, engine: Optional[Engine] = None) -> list[DeviceRecord]:
    with session_scope(engine=engine) as session:
        stmt = select(USBDevice).order_by(USBDevice.last_seen.desc())
        if status_filter:
            stmt = stmt.where(USBDevice.status == status_filter)
        devices = session.scalars(stmt).all()
        return [_to_device_record(d) for d in devices]


def get_device(device_id: int, engine: Optional[Engine] = None) -> Optional[DeviceRecord]:
    with session_scope(engine=engine) as session:
        device = session.get(USBDevice, device_id)
        return _to_device_record(device) if device else None


def get_device_events(device_id: int, engine: Optional[Engine] = None) -> list[DeviceEventRecord]:
    with session_scope(engine=engine) as session:
        stmt = select(DeviceEvent).where(DeviceEvent.device_id == device_id).order_by(DeviceEvent.timestamp.desc())
        events = session.scalars(stmt).all()
        return [_to_event_record(e) for e in events]


def get_device_counts(engine: Optional[Engine] = None) -> DeviceCounts:
    with session_scope(engine=engine) as session:
        def count_where(status: Optional[str] = None) -> int:
            stmt = select(func.count(USBDevice.id))
            if status:
                stmt = stmt.where(USBDevice.status == status)
            return session.scalar(stmt) or 0

        return DeviceCounts(
            total=count_where(),
            trusted=count_where(DeviceStatus.TRUSTED.value),
            blocked=count_where(DeviceStatus.BLOCKED.value),
            unknown=count_where(DeviceStatus.UNKNOWN.value),
            temporary=count_where(DeviceStatus.TEMPORARY.value),
        )
