"""
USB monitor backend selection.

- SIMULATION_MODE=true (the default, and required on non-Windows) ->
  SimulationUSBMonitor, regardless of platform.
- SIMULATION_MODE=false AND running on Windows -> WindowsUSBMonitor
  (real detection).
- SIMULATION_MODE=false AND NOT on Windows -> refuse clearly rather
  than silently falling back to simulation, since that would produce
  fake events under a configuration that explicitly asked for real ones.
"""

from __future__ import annotations

from app.config.settings import settings
from app.core.exceptions import USBDetectionError
from app.usb.base import USBMonitorBase, USBEventCallback
from app.usb.simulation_monitor import SimulationUSBMonitor


def create_usb_monitor(on_event: USBEventCallback, simulation_override: bool | None = None) -> USBMonitorBase:
    """
    Build the appropriate USB monitor for the current environment.

    `simulation_override` lets a caller (e.g. a settings toggle in the
    GUI) force one mode or the other without changing the .env file;
    None means "use settings.simulation_mode".
    """
    use_simulation = settings.simulation_mode if simulation_override is None else simulation_override

    if use_simulation:
        return SimulationUSBMonitor(on_event)

    if not settings.is_windows:
        raise USBDetectionError(
            "SIMULATION_MODE is disabled but this is not a Windows machine. "
            "Real USB detection requires Windows. Enable SIMULATION_MODE "
            "for development on this platform."
        )

    from app.usb.windows_monitor import WindowsUSBMonitor
    return WindowsUSBMonitor(on_event)
