"""
USBDeviceInfo: the canonical structure produced by every USB monitoring
backend (Windows/WMI or simulation) - Section 8's required fields.

This is intentionally backend-agnostic: app/usb/windows_monitor.py and
app/usb/simulation_monitor.py both produce instances of this class, so
nothing downstream (fingerprinting, classification, policy engine in
Phase 7, device registry in Phase 6) needs to know or care which one
generated a given event.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
from typing import Optional

from app.core.enums import DeviceEventType


@dataclasses.dataclass
class USBDeviceInfo:
    event_type: str  # DeviceEventType value: CONNECTED or REMOVED

    # Identity (Section 8). Not all devices provide all fields - Section 10
    # requires graceful handling of missing values, never an assumption
    # that a field is present.
    name: Optional[str] = None
    manufacturer: Optional[str] = None
    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    serial_number: Optional[str] = None
    pnp_device_id: Optional[str] = None
    raw_device_class: Optional[str] = None  # OS-reported class string, pre-classification
    drive_letter: Optional[str] = None

    computer_name: Optional[str] = None
    timestamp: dt.datetime = dataclasses.field(default_factory=dt.datetime.utcnow)
    is_simulated: bool = False

    def as_metadata_dict(self) -> dict:
        """Everything except event_type/timestamp - suitable for storing
        as DeviceEvent.raw_metadata (Section 8: 'connection timestamp').
        """
        return {
            "name": self.name,
            "manufacturer": self.manufacturer,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": self.serial_number,
            "pnp_device_id": self.pnp_device_id,
            "raw_device_class": self.raw_device_class,
            "drive_letter": self.drive_letter,
            "computer_name": self.computer_name,
            "is_simulated": self.is_simulated,
        }

    def as_metadata_json(self) -> str:
        return json.dumps(self.as_metadata_dict(), default=str)

    def is_connect(self) -> bool:
        return self.event_type == DeviceEventType.CONNECTED.value

    def is_remove(self) -> bool:
        return self.event_type == DeviceEventType.REMOVED.value

    def display_name(self) -> str:
        return self.name or self.pnp_device_id or "Unknown USB device"
