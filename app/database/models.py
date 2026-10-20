"""
ORM models for the USB Security System database.

Tables (Section 18):
    users, device_fingerprints, usb_devices, device_events,
    policies, security_alerts, audit_logs, system_settings

Design notes:
- All timestamps are stored as timezone-naive UTC datetimes; the UI layer
  (Phase 4+) is responsible for local-time display.
- `audit_logs` intentionally exposes no update/delete-friendly fields
  (no `updated_at`) and Phase 3+ application code must never issue
  UPDATE/DELETE against it from the normal GUI (Section 15) - only
  INSERT and SELECT. This is enforced at the application layer in the
  repository module added later, not by a DB trigger, since SQLite
  triggers would complicate the "no unnecessary dependencies" rule.
- JSON-shaped data (policy conditions, raw device metadata) is stored as
  TEXT containing JSON; SQLite has no native JSON validation, so the
  policy engine (Phase 7) is responsible for validating shape on write.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import (
    ForeignKey,
    String,
    Integer,
    Boolean,
    DateTime,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def utcnow() -> dt.datetime:
    return dt.datetime.utcnow()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)  # UserRole enum value
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_login_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role}>"


# ---------------------------------------------------------------------------
# Device fingerprints
# ---------------------------------------------------------------------------
class DeviceFingerprint(Base):
    __tablename__ = "device_fingerprints"

    id: Mapped[int] = mapped_column(primary_key=True)
    vendor_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    product_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    serial_number: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    pnp_device_id: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    manufacturer: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_class: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fingerprint_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)

    devices: Mapped[list["USBDevice"]] = relationship(back_populates="fingerprint")

    def __repr__(self) -> str:
        return f"<DeviceFingerprint id={self.id} hash={self.fingerprint_hash[:12]}...>"


# ---------------------------------------------------------------------------
# USB devices (the registry)
# ---------------------------------------------------------------------------
class USBDevice(Base):
    __tablename__ = "usb_devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint_id: Mapped[int] = mapped_column(ForeignKey("device_fingerprints.id"), nullable=False, index=True)

    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    manufacturer: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    vendor_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    product_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    serial_number: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    pnp_device_id: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    device_class: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)   # DeviceClass enum value
    device_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)    # e.g. "Mass Storage"

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")  # DeviceStatus enum value

    first_seen: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    connection_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    approved_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)

    # Temporary authorization support (Section 11 "Temporary Devices")
    temporary_expires_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)

    fingerprint: Mapped["DeviceFingerprint"] = relationship(back_populates="devices")
    events: Mapped[list["DeviceEvent"]] = relationship(back_populates="device")
    alerts: Mapped[list["SecurityAlert"]] = relationship(back_populates="device")

    def __repr__(self) -> str:
        return f"<USBDevice id={self.id} name={self.name!r} status={self.status}>"


# ---------------------------------------------------------------------------
# Device events (connect / remove history)
# ---------------------------------------------------------------------------
class DeviceEvent(Base):
    __tablename__ = "device_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("usb_devices.id"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)  # DeviceEventType enum value
    result: Mapped[str] = mapped_column(String(16), nullable=False, default="DETECTED")  # EnforcementResult
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    computer_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    drive_letter: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)

    timestamp: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    raw_metadata: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string

    device: Mapped["USBDevice"] = relationship(back_populates="events")

    __table_args__ = (
        Index("ix_device_events_device_timestamp", "device_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<DeviceEvent id={self.id} device_id={self.device_id} type={self.event_type} result={self.result}>"


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)  # lower = evaluated first
    conditions: Mapped[str] = mapped_column(Text, nullable=False, default="{}")  # JSON string
    action: Mapped[str] = mapped_column(String(16), nullable=False)  # PolicyAction enum value
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")  # PolicyStatus enum value

    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<Policy id={self.id} name={self.name!r} action={self.action} priority={self.priority}>"


# ---------------------------------------------------------------------------
# Security alerts
# ---------------------------------------------------------------------------
class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # AlertSeverity enum value
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)            # AlertType enum value

    device_id: Mapped[Optional[int]] = mapped_column(ForeignKey("usb_devices.id"), nullable=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    computer_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    description: Mapped[str] = mapped_column(Text, nullable=False)

    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)

    device: Mapped[Optional["USBDevice"]] = relationship(back_populates="alerts")

    def __repr__(self) -> str:
        return f"<SecurityAlert id={self.id} severity={self.severity} type={self.alert_type}>"


# ---------------------------------------------------------------------------
# Audit logs (append-only)
# ---------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)

    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    computer_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)  # AuditEventType enum value
    device_id: Mapped[Optional[int]] = mapped_column(ForeignKey("usb_devices.id"), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    result: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)   # EnforcementResult / outcome
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="INFO")  # AuditSeverity enum value
    description: Mapped[str] = mapped_column(Text, nullable=False)

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} event_type={self.event_type} result={self.result}>"


# ---------------------------------------------------------------------------
# System settings (key/value)
# ---------------------------------------------------------------------------
class SystemSetting(Base):
    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    updated_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)

    __table_args__ = (
        UniqueConstraint("key", name="uq_system_settings_key"),
    )

    def __repr__(self) -> str:
        return f"<SystemSetting key={self.key!r} value={self.value!r}>"
