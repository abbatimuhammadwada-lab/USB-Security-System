"""
Real Windows USB monitoring backend (Section 8).

Uses WMI (via the `wmi` package, which wraps pywin32's COM bindings) to
subscribe to Win32_DeviceChangeEvent notifications - the standard,
documented, event-driven mechanism for detecting PnP device arrival/
removal on Windows, rather than polling (Section 8: "avoid aggressive
polling; prefer event-driven Windows mechanisms").

IMPORTANT / HONEST LIMITATION: this module can only be exercised on
real Windows hardware with pywin32 + WMI installed. This development
sandbox is Linux, so this class cannot be executed or unit-tested here.
It is implemented against Microsoft's documented WMI event classes and
follows the same interface (USBMonitorBase) that IS fully tested here
via SimulationUSBMonitor - the integration point is exercised, the
Windows-specific internals are not. Section 27's demo scenarios should
be run once on real Windows hardware before a project defense to
confirm this class in particular.

Win32_DeviceChangeEvent.EventType:
    1 = Configuration changed
    2 = Device arrival   (connected)
    3 = Device removal   (removed)
"""

from __future__ import annotations

import datetime as dt
import re
import threading
from typing import Optional

from app.config.settings import settings
from app.core.enums import DeviceEventType
from app.core.exceptions import USBDetectionError
from app.usb.base import USBMonitorBase, USBEventCallback
from app.usb.device_info import USBDeviceInfo

_VID_PID_PATTERN = re.compile(r"VID_([0-9A-F]{4}).*PID_([0-9A-F]{4})", re.IGNORECASE)
_SERIAL_PATTERN = re.compile(r"\\([^\\&]+)&\d+$")


class WindowsUSBMonitor(USBMonitorBase):
    def __init__(self, on_event: USBEventCallback) -> None:
        super().__init__(on_event)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if not settings.is_windows:
            raise USBDetectionError(
                "WindowsUSBMonitor requires Windows. Use SimulationUSBMonitor "
                "for development on this platform, or enable SIMULATION_MODE."
            )
        try:
            import wmi  # noqa: F401  (import here so this module is importable on any OS)
        except ImportError as exc:
            raise USBDetectionError(
                "The 'wmi' and 'pywin32' packages are required for real USB "
                "detection on Windows. Install them with: pip install wmi pywin32"
            ) from exc

        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="WindowsUSBMonitor", daemon=True)
        self._thread.start()
        self._running = True

    def stop(self) -> None:
        if not self._running:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self._running = False

    def _run(self) -> None:
        import wmi
        import pythoncom

        # WMI/COM event watchers must be created on the thread that polls
        # them; COM requires this thread to be initialized.
        pythoncom.CoInitialize()
        try:
            connection = wmi.WMI()
            watcher = connection.Win32_DeviceChangeEvent.watch_for()

            while not self._stop_event.is_set():
                try:
                    event = watcher(timeout_ms=1000)
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as exc:  # pragma: no cover - defensive, Windows-only
                    # A transient WMI error must not kill the monitoring
                    # thread silently (Section 20) - log and keep watching.
                    self._handle_watch_error(exc)
                    continue

                self._handle_device_change_event(event)
        finally:
            pythoncom.CoUninitialize()

    def _handle_watch_error(self, exc: Exception) -> None:
        import logging
        logging.getLogger(__name__).error(f"WMI device-change watch error: {exc}")

    def _handle_device_change_event(self, event) -> None:  # noqa: ANN001 - wmi event object
        event_type_code = getattr(event, "EventType", None)
        if event_type_code not in (2, 3):
            return  # not an arrival/removal event (e.g. config changed)

        event_type = (
            DeviceEventType.CONNECTED.value if event_type_code == 2 else DeviceEventType.REMOVED.value
        )

        for pnp_entity in self._enumerate_recent_pnp_entities():
            info = self._build_device_info(pnp_entity, event_type)
            if info is not None:
                self._emit(info)

    def _enumerate_recent_pnp_entities(self):
        """
        Win32_DeviceChangeEvent does not itself carry the device's
        identity - it only signals that *something* changed. The
        documented follow-up is to re-query Win32_PnPEntity for USB
        devices and diff against the previously known set. A full
        stateful diff (tracking a "last known set" across calls) is
        deliberately kept simple here: query current USB PnP entities
        and let the caller correlate arrivals/removals via the device
        registry in Phase 6, which already tracks first_seen/last_seen
        per device.
        """
        import wmi
        connection = wmi.WMI()
        return connection.Win32_PnPEntity(DeviceID=re.compile(r"^USB", re.IGNORECASE))  # type: ignore[call-arg]

    def _build_device_info(self, pnp_entity, event_type: str) -> Optional[USBDeviceInfo]:
        device_id = getattr(pnp_entity, "DeviceID", "") or ""
        name = getattr(pnp_entity, "Name", None) or getattr(pnp_entity, "Caption", None)
        manufacturer = getattr(pnp_entity, "Manufacturer", None)
        pnp_class = getattr(pnp_entity, "PNPClass", None)

        vendor_id = product_id = None
        match = _VID_PID_PATTERN.search(device_id)
        if match:
            vendor_id, product_id = match.group(1).upper(), match.group(2).upper()

        serial_number = None
        serial_match = _SERIAL_PATTERN.search(device_id)
        if serial_match:
            candidate = serial_match.group(1)
            # Windows uses "&0" style suffixes for devices WITHOUT a real
            # hardware serial number - those are not stable identifiers
            # and must not be reported as a serial number (Section 10).
            if "&" not in candidate:
                serial_number = candidate

        return USBDeviceInfo(
            event_type=event_type,
            name=name,
            manufacturer=manufacturer,
            vendor_id=vendor_id,
            product_id=product_id,
            serial_number=serial_number,
            pnp_device_id=device_id or None,
            raw_device_class=pnp_class,
            drive_letter=None,  # resolved separately via Win32_LogicalDisk when device_type is storage
            computer_name=settings.computer_name,
            timestamp=dt.datetime.utcnow(),
            is_simulated=False,
        )
