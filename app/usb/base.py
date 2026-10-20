"""
Abstract USB monitoring interface.

Both the real Windows backend (windows_monitor.py) and the simulation
backend (simulation_monitor.py) implement this same interface, so the
rest of the application (device registry in Phase 6, policy engine in
Phase 7, GUI wiring) works identically regardless of which one is
running - it only ever talks to USBMonitorBase.
"""

from __future__ import annotations

import abc
from typing import Callable

from app.usb.device_info import USBDeviceInfo

USBEventCallback = Callable[[USBDeviceInfo], None]


class USBMonitorBase(abc.ABC):
    """
    Subclasses run event detection on a background thread and invoke
    the registered callback once per detected connect/remove event.
    The callback is invoked from the monitor's background thread, NOT
    the caller's thread - callers that touch Qt widgets from it must
    marshal back to the GUI thread (handled when this is wired into the
    UI in a later phase).
    """

    def __init__(self, on_event: USBEventCallback) -> None:
        self._on_event = on_event
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @abc.abstractmethod
    def start(self) -> None:
        """Begin monitoring. Must be safe to call only once per instance."""

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop monitoring and release any OS resources / threads."""

    def _emit(self, info: USBDeviceInfo) -> None:
        self._on_event(info)
