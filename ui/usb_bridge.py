"""
Thread-safe bridge between the USB monitor's background thread
(app/usb/base.py: callbacks fire off-thread) and the Qt GUI thread.

Qt signal/slot connections across threads are safe by default (Qt
auto-detects the receiver lives on a different thread and queues the
delivery), so this bridge is intentionally thin: the monitor's
callback just emits a signal, and any GUI code connects to that signal
normally, no manual locking required.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from app.usb.device_info import USBDeviceInfo


class USBEventBridge(QObject):
    device_event = Signal(object)  # emits a USBDeviceInfo

    def on_monitor_event(self, info: USBDeviceInfo) -> None:
        """Pass this method as the `on_event` callback to create_usb_monitor()."""
        self.device_event.emit(info)
