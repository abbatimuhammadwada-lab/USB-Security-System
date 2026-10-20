"""
Simulation USB monitor (Section 24).

Lets developers and the project-defense demo inject synthetic USB
connect/remove events without touching real hardware, so the whole
detect -> identify -> evaluate -> allow/block -> alert -> log pipeline
can be exercised on any machine, including this non-Windows sandbox.

Every event produced here has is_simulated=True (USBDeviceInfo), which
the audit log and UI (later phases) must display distinctly from real
events - Section 24 requires simulated events are never confused with
real ones.

Note on terminology: Section 24 lists event "types" such as
AUTHORIZED_DEVICE, UNKNOWN_DEVICE, BLACKLISTED_DEVICE, and
POLICY_VIOLATION. At the USB DETECTION layer (this module), the system
only knows a device connected or was removed - authorization status is
a POLICY decision made in Phase 7, not something the USB layer itself
determines. The preset profiles below are named to make it easy to
inject a device that a policy engine WOULD classify as trusted/unknown/
blacklisted-looking once that engine exists, but this module makes no
such determination itself.
"""

from __future__ import annotations

import queue
import threading
import datetime as dt
from typing import Optional

from app.config.settings import settings
from app.core.enums import DeviceEventType
from app.usb.base import USBMonitorBase, USBEventCallback
from app.usb.device_info import USBDeviceInfo

# Convenience profiles for manual testing / the project-defense demo.
# These are just plausible metadata bundles - nothing about them is
# "authorized" or "blacklisted" until the (future) device registry and
# policy engine say so.
DEVICE_PROFILES: dict[str, dict] = {
    "kingston_datatraveler": dict(
        name="Kingston DataTraveler 3.0",
        manufacturer="Kingston Technology",
        vendor_id="0951",
        product_id="1666",
        serial_number="E0D55EA571A6C3FA1234",
        pnp_device_id=r"USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_PMAP\E0D55EA571A6C3FA1234&0",
        raw_device_class="USB Mass Storage",
        drive_letter="E:",
    ),
    "logitech_mouse": dict(
        name="Logitech USB Optical Mouse",
        manufacturer="Logitech",
        vendor_id="046D",
        product_id="C077",
        serial_number=None,
        pnp_device_id=r"HID\VID_046D&PID_C077\6&1A2B3C4D&0&0000",
        raw_device_class="Keyboard",  # intentionally noisy metadata; classifier should still work via other fields
        drive_letter=None,
    ),
    "unknown_no_serial": dict(
        name="Generic USB Storage Device",
        manufacturer=None,
        vendor_id="1234",
        product_id="5678",
        serial_number=None,
        pnp_device_id=None,
        raw_device_class="USB Mass Storage",
        drive_letter="F:",
    ),
    "no_metadata_device": dict(
        name=None,
        manufacturer=None,
        vendor_id=None,
        product_id=None,
        serial_number=None,
        pnp_device_id=None,
        raw_device_class=None,
        drive_letter=None,
    ),
}


class SimulationUSBMonitor(USBMonitorBase):
    """
    Queue-driven simulation monitor. Runs a background worker thread so
    its threading model matches the real WindowsUSBMonitor (callbacks
    always arrive off the calling thread), even though the "hardware"
    here is just injected Python calls.
    """

    def __init__(self, on_event: USBEventCallback) -> None:
        super().__init__(on_event)
        self._queue: "queue.Queue[USBDeviceInfo]" = queue.Queue()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="SimulationUSBMonitor", daemon=True)
        self._thread.start()
        self._running = True

    def stop(self) -> None:
        if not self._running:
            return
        self._stop_event.set()
        self._queue.put_nowait(None)  # type: ignore[arg-type]  # wake the worker
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._running = False

    def _run(self) -> None:
        while not self._stop_event.is_set():
            item = self._queue.get()
            if item is None:
                continue
            self._emit(item)

    # --- injection API -------------------------------------------------
    def inject_connect(
        self,
        profile: Optional[str] = None,
        computer_name: Optional[str] = None,
        **overrides,
    ) -> USBDeviceInfo:
        """Inject a simulated device-connected event. Pass `profile` to
        use one of DEVICE_PROFILES, and/or **overrides to customize
        individual fields (e.g. inject_connect('kingston_datatraveler',
        serial_number='DIFFERENT123'))."""
        fields = dict(DEVICE_PROFILES.get(profile, {})) if profile else {}
        fields.update(overrides)
        info = USBDeviceInfo(
            event_type=DeviceEventType.CONNECTED.value,
            computer_name=computer_name or settings.computer_name,
            is_simulated=True,
            timestamp=dt.datetime.utcnow(),
            **fields,
        )
        self._queue.put_nowait(info)
        return info

    def inject_remove(
        self,
        profile: Optional[str] = None,
        computer_name: Optional[str] = None,
        **overrides,
    ) -> USBDeviceInfo:
        fields = dict(DEVICE_PROFILES.get(profile, {})) if profile else {}
        fields.update(overrides)
        info = USBDeviceInfo(
            event_type=DeviceEventType.REMOVED.value,
            computer_name=computer_name or settings.computer_name,
            is_simulated=True,
            timestamp=dt.datetime.utcnow(),
            **fields,
        )
        self._queue.put_nowait(info)
        return info
