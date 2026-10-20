"""
Detached data-transfer objects for the device registry.

Every repository function that touches the database returns one of
these instead of a live ORM object, so callers (GUI code especially)
can hold onto and read the result after the originating session_scope()
has closed, without triggering SQLAlchemy's DetachedInstanceError -
the same pattern established in app/security/auth.py's AuthenticatedUser.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class DeviceRecord:
    id: int
    fingerprint_id: int
    name: Optional[str]
    manufacturer: Optional[str]
    vendor_id: Optional[str]
    product_id: Optional[str]
    serial_number: Optional[str]
    pnp_device_id: Optional[str]
    device_class: Optional[str]
    device_type: Optional[str]
    status: str
    first_seen: dt.datetime
    last_seen: dt.datetime
    connection_count: int
    approved_by: Optional[int]
    approved_at: Optional[dt.datetime]
    temporary_expires_at: Optional[dt.datetime]

    def display_name(self) -> str:
        return self.name or self.pnp_device_id or f"Device #{self.id}"


@dataclass(frozen=True)
class DeviceEventRecord:
    id: int
    device_id: int
    event_type: str
    result: str
    is_simulated: bool
    user_id: Optional[int]
    computer_name: Optional[str]
    drive_letter: Optional[str]
    timestamp: dt.datetime


@dataclass(frozen=True)
class DeviceCounts:
    total: int
    trusted: int
    blocked: int
    unknown: int
    temporary: int
