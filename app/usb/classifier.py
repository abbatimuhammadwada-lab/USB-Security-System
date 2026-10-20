"""
Device classification (Section 9).

This is deliberately simple, transparent, keyword/prefix matching
against whatever class/description strings Windows (or the simulation
layer) reports - NOT machine learning, NOT a device-ID lookup database.
Rule 13 / Section 13 requires the app never claim more sophistication
than it has, so this stays a short, readable if/elif chain rather than
a black box.

When nothing matches confidently, DeviceClass.UNKNOWN is returned - the
UI must surface that as "could not be confidently classified" per
Section 9, not silently guess.
"""

from __future__ import annotations

from app.core.enums import DeviceClass
from app.usb.device_info import USBDeviceInfo

# Ordered (most specific first) keyword -> DeviceClass rules, matched
# against the lowercased raw_device_class and name/PnP device id.
_KEYWORD_RULES: list[tuple[tuple[str, ...], DeviceClass]] = [
    (("usbstor", "mass storage", "disk", "flash drive", "datatraveler"), DeviceClass.MASS_STORAGE),
    (("keyboard", "hid keyboard"), DeviceClass.KEYBOARD),
    (("mouse", "hid mouse", "pointing device"), DeviceClass.MOUSE),
    (("android", "iphone", "smartphone", "mtp", "portable device"), DeviceClass.SMARTPHONE),
    (("camera", "webcam", "imaging"), DeviceClass.CAMERA),
    (("audio", "headset", "microphone", "speaker"), DeviceClass.AUDIO),
    (("network adapter", "ethernet", "wi-fi", "wlan", "net"), DeviceClass.NETWORK_ADAPTER),
]


def classify_device(info: USBDeviceInfo) -> DeviceClass:
    """
    Best-effort classification from available metadata strings.

    Checks fields in priority order - name first, then the OS-reported
    class string, then the PnP device ID - rather than merging them into
    one blob. A device's human-readable name is the most reliable single
    signal; the raw OS class string can be generic or misleading (e.g.
    many HID peripherals report a broad "HID"/"Keyboard" class even for
    a mouse, since both are Human Interface Devices), so it should not
    be allowed to override a clear name match.
    """
    fields_in_priority_order = [info.name, info.raw_device_class, info.pnp_device_id]

    for field in fields_in_priority_order:
        if not field:
            continue
        field_lower = field.lower()
        for keywords, device_class in _KEYWORD_RULES:
            if any(keyword in field_lower for keyword in keywords):
                return device_class

    if any(fields_in_priority_order):
        return DeviceClass.OTHER_PERIPHERAL

    return DeviceClass.UNKNOWN
