"""
Privilege detection utilities (Section 22).

The application must always know - and truthfully report - whether it is
running with the administrator privileges required for certain enforcement
and device-management operations. This module never performs silent
elevation; it only detects and reports current privilege state.
"""

from __future__ import annotations

import ctypes
import os
import platform


def is_running_as_admin() -> bool:
    """
    Return True if the current process has administrator privileges.

    On Windows this checks the process token via the shell32 API.
    On non-Windows platforms (used only for development/testing of the
    non-Windows-specific parts of this app) this checks for a root/uid 0
    process as the closest equivalent.
    """
    system = platform.system()
    if system == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            # If the check itself fails, we must not assume elevated
            # privileges - fail closed.
            return False
    else:
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            return False


def privilege_warning_message() -> str:
    """User-facing explanation shown when elevated privileges are absent."""
    return (
        "This application is not running with administrator privileges. "
        "USB detection, device inventory, alerting, audit logging, and "
        "read-only dashboard features are fully available. Features that "
        "modify Windows device state directly (enforcement/blocking of a "
        "specific unauthorized device) require administrator privileges. "
        "Until the application is restarted 'Run as administrator', "
        "enforcement attempts will be logged with the result BLOCKING_FAILED "
        "rather than silently succeeding or being skipped."
    )
