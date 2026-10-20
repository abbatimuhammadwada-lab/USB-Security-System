"""
Windows device enforcement (Section 4).

The one legitimate, documented mechanism for disabling a SPECIFIC,
already-enumerated device instance from a user-mode application without
a driver of our own is SetupAPI's device-instance disable, which the
`pnputil` command-line tool exposes as `pnputil /disable-device
/deviceid "<PNP device ID>"`. This requires administrator privileges.

HONEST LIMITATION (same as app/usb/windows_monitor.py): this has not
been executed against real Windows hardware in this development sandbox
(Linux). The command and its documented behavior are implemented
faithfully, but validate this on Windows before relying on it, and
before a project defense.

This module NEVER claims success it did not observe. If privileges are
missing, the platform isn't Windows, no PnP device ID is available, or
the command itself fails or times out, it returns BLOCKING_FAILED with
a specific reason - never BLOCKED.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from app.config.settings import settings
from app.core.enums import EnforcementResult
from app.utils.privileges import is_running_as_admin

_ENFORCEMENT_TIMEOUT_SECONDS = 15


@dataclass(frozen=True)
class EnforcementOutcome:
    result: str  # EnforcementResult.BLOCKED.value or EnforcementResult.BLOCKING_FAILED.value
    reason: str


def attempt_block_device(pnp_device_id: str | None) -> EnforcementOutcome:
    """
    Attempt to disable the given PnP device instance via pnputil.
    Returns an EnforcementOutcome - never raises for expected failure
    modes (missing privileges, wrong platform, missing device id,
    command failure); those are all legitimate BLOCKING_FAILED outcomes,
    not exceptions, so callers always get a definite answer to record.
    """
    if not pnp_device_id:
        return EnforcementOutcome(
            EnforcementResult.BLOCKING_FAILED.value,
            "No PnP device ID is available for this device; cannot target a specific "
            "device instance for enforcement.",
        )

    if not settings.is_windows:
        return EnforcementOutcome(
            EnforcementResult.BLOCKING_FAILED.value,
            "Enforcement requires Windows (pnputil is a Windows-only tool); "
            "this platform cannot disable the device.",
        )

    if not is_running_as_admin():
        return EnforcementOutcome(
            EnforcementResult.BLOCKING_FAILED.value,
            "Administrator privileges are required to disable a device instance. "
            "Restart the application 'Run as administrator' to enable enforcement.",
        )

    try:
        completed = subprocess.run(
            ["pnputil", "/disable-device", "/deviceid", pnp_device_id],
            capture_output=True, text=True, timeout=_ENFORCEMENT_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return EnforcementOutcome(
            EnforcementResult.BLOCKING_FAILED.value,
            "pnputil.exe was not found on this system.",
        )
    except subprocess.TimeoutExpired:
        return EnforcementOutcome(
            EnforcementResult.BLOCKING_FAILED.value,
            f"pnputil did not complete within {_ENFORCEMENT_TIMEOUT_SECONDS} seconds.",
        )
    except OSError as exc:
        return EnforcementOutcome(
            EnforcementResult.BLOCKING_FAILED.value,
            f"Failed to invoke pnputil: {exc}",
        )

    if completed.returncode == 0:
        return EnforcementOutcome(
            EnforcementResult.BLOCKED.value,
            "pnputil successfully disabled the device instance.",
        )

    return EnforcementOutcome(
        EnforcementResult.BLOCKING_FAILED.value,
        f"pnputil exited with code {completed.returncode}: "
        f"{(completed.stderr or completed.stdout or '').strip()[:300]}",
    )
