"""
Central enumerations used across the entire application.

Keeping these in one module prevents "magic string" drift between the
USB detection layer, the policy engine, the enforcement layer, the
alerting system, and the UI - they all import from here.
"""

from enum import Enum


class UserRole(str, Enum):
    ADMINISTRATOR = "ADMINISTRATOR"
    SECURITY_ANALYST = "SECURITY_ANALYST"


class DeviceStatus(str, Enum):
    """
    Lifecycle status of a USB device as tracked in the device registry.
    Distinct from EnforcementResult, which describes what happened the
    moment the device was last connected.
    """
    TRUSTED = "TRUSTED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    TEMPORARY = "TEMPORARY"


class DeviceEventType(str, Enum):
    CONNECTED = "CONNECTED"
    REMOVED = "REMOVED"


class DeviceClass(str, Enum):
    MASS_STORAGE = "USB Mass Storage"
    KEYBOARD = "Keyboard"
    MOUSE = "Mouse"
    SMARTPHONE = "Smartphone"
    CAMERA = "Camera"
    AUDIO = "Audio device"
    NETWORK_ADAPTER = "Network adapter"
    OTHER_PERIPHERAL = "Other USB peripheral"
    UNKNOWN = "Unknown device"


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ALERT = "ALERT"
    LOG_ONLY = "LOG_ONLY"


class PolicyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertType(str, Enum):
    UNKNOWN_USB = "UNKNOWN_USB"
    BLACKLISTED_USB = "BLACKLISTED_USB"
    REPEATED_UNAUTHORIZED_ATTEMPTS = "REPEATED_UNAUTHORIZED_ATTEMPTS"
    RAPID_CONNECT_DISCONNECT = "RAPID_CONNECT_DISCONNECT"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    AFTER_HOURS_CONNECTION = "AFTER_HOURS_CONNECTION"


class AuditEventType(str, Enum):
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    FAILED_LOGIN = "FAILED_LOGIN"
    USB_CONNECTED = "USB_CONNECTED"
    USB_REMOVED = "USB_REMOVED"
    DEVICE_APPROVED = "DEVICE_APPROVED"
    DEVICE_BLOCKED = "DEVICE_BLOCKED"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    POLICY_CREATED = "POLICY_CREATED"
    POLICY_CHANGED = "POLICY_CHANGED"
    POLICY_DELETED = "POLICY_DELETED"
    ACCESS_DENIED = "ACCESS_DENIED"
    ACCESS_ALLOWED = "ACCESS_ALLOWED"
    ALERT_GENERATED = "ALERT_GENERATED"
    REPORT_GENERATED = "REPORT_GENERATED"
    CONFIGURATION_CHANGED = "CONFIGURATION_CHANGED"


class AuditSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EnforcementResult(str, Enum):
    """
    The ground-truth outcome of an enforcement attempt for a single
    connection event. The UI must always display one of these exact
    values - never a value implying an action occurred when it did not.
    """
    DETECTED = "DETECTED"          # seen, not yet evaluated
    AUTHORIZED = "AUTHORIZED"      # policy evaluation says allow
    UNAUTHORIZED = "UNAUTHORIZED"  # policy evaluation says deny
    ALLOWED = "ALLOWED"            # access was granted (no enforcement needed)
    BLOCKED = "BLOCKED"            # enforcement action succeeded
    BLOCKING_FAILED = "BLOCKING_FAILED"  # enforcement attempted, could not complete
    REMOVED = "REMOVED"            # device physically disconnected
    UNKNOWN = "UNKNOWN"            # device could not be classified/identified
