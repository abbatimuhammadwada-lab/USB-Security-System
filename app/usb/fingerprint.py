"""
Device fingerprinting (Section 10).

Builds a stable identifier for a physical USB device from whichever
attributes it actually reports. Vendor ID + Product ID + Serial Number
is the strongest combination (most mass-storage devices provide all
three); many cheap/no-name peripherals omit the serial number, so this
module degrades gracefully rather than failing or refusing to fingerprint.

Fingerprint strength is explicitly reported (STRONG / WEAK) so later
phases (policy engine, device registry) can treat a WEAK fingerprint
with appropriate caution - e.g. two different physical devices without
serial numbers but with the same vendor/product ID will collide, and
the system should not silently pretend that never happens.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from app.core.exceptions import DeviceFingerprintError
from app.usb.device_info import USBDeviceInfo


@dataclass(frozen=True)
class DeviceFingerprint:
    fingerprint_hash: str
    strength: str  # "STRONG" or "WEAK"
    vendor_id: str | None
    product_id: str | None
    serial_number: str | None
    pnp_device_id: str | None
    manufacturer: str | None
    device_class: str | None


def _normalize(value: str | None) -> str:
    return (value or "").strip().upper()


def compute_fingerprint(info: USBDeviceInfo) -> DeviceFingerprint:
    """
    Compute a fingerprint for a detected device.

    Strategy, in order of preference:
    1. vendor_id + product_id + serial_number  -> STRONG (identifies the
       exact physical unit, since serial numbers are unique per device
       for compliant hardware)
    2. vendor_id + product_id + pnp_device_id  -> STRONG (PnP device IDs
       on Windows are unique per physical device instance path even
       without a hardware serial number, for most device classes)
    3. vendor_id + product_id alone            -> WEAK (identifies the
       device MODEL, not the specific unit - will collide across
       identical peripherals from the same vendor)
    4. name + manufacturer + raw_device_class  -> WEAK (last resort for
       devices that expose no vendor/product ID at all)

    Raises DeviceFingerprintError only if literally no usable identifying
    information exists at all - which should be very rare.
    """
    vendor_id = _normalize(info.vendor_id)
    product_id = _normalize(info.product_id)
    serial = _normalize(info.serial_number)
    pnp_id = _normalize(info.pnp_device_id)
    manufacturer = _normalize(info.manufacturer)
    device_class = _normalize(info.raw_device_class)
    name = _normalize(info.name)

    if vendor_id and product_id and serial:
        basis = f"VP:{vendor_id}:{product_id}:SN:{serial}"
        strength = "STRONG"
    elif vendor_id and product_id and pnp_id:
        basis = f"VP:{vendor_id}:{product_id}:PNP:{pnp_id}"
        strength = "STRONG"
    elif vendor_id and product_id:
        basis = f"VP:{vendor_id}:{product_id}"
        strength = "WEAK"
    elif name or manufacturer or device_class:
        basis = f"NM:{name}:{manufacturer}:{device_class}"
        strength = "WEAK"
    else:
        raise DeviceFingerprintError(
            "Unable to compute a device fingerprint: the device reported "
            "no vendor/product ID, serial number, PnP device ID, name, "
            "manufacturer, or device class."
        )

    fingerprint_hash = hashlib.sha256(basis.encode("utf-8")).hexdigest()

    return DeviceFingerprint(
        fingerprint_hash=fingerprint_hash,
        strength=strength,
        vendor_id=info.vendor_id,
        product_id=info.product_id,
        serial_number=info.serial_number,
        pnp_device_id=info.pnp_device_id,
        manufacturer=info.manufacturer,
        device_class=info.raw_device_class,
    )
