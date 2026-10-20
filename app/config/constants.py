"""
Static constants that are not environment-configurable.
"""

APP_TITLE = "USB Device Intrusion Detection, Access Control and Audit Logging System"
ORG_NAME = "Final Year Cybersecurity Project"

MIN_PYTHON_VERSION = (3, 12)

# Windows Device setup class GUIDs relevant to USB monitoring (used from
# Phase 5 onward when registering for WM_DEVICECHANGE / WMI event watchers).
GUID_DEVINTERFACE_USB_DEVICE = "A5DCBF10-6530-11D2-901F-00C04FB951ED"
GUID_DEVINTERFACE_VOLUME = "53F5630D-B6BF-11D0-94F2-00A0C91EFB8B"

DEFAULT_ADMIN_USERNAME_ENV = "DEFAULT_ADMIN_USERNAME"
DEFAULT_ADMIN_PASSWORD_ENV = "DEFAULT_ADMIN_PASSWORD"
