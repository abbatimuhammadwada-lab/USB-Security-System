"""
Application-wide exception hierarchy.

Every module raises one of these (never a bare Exception) so the UI
layer and the top-level error handler in main.py can catch, log, and
present a user-friendly message without ever leaking a raw traceback
to a non-administrator user (see Section 20 / Section 25 requirements).
"""


class USBSecuritySystemError(Exception):
    """Base class for all application-raised errors."""


class ConfigurationError(USBSecuritySystemError):
    """Raised when required configuration/environment values are missing or invalid."""


class DatabaseError(USBSecuritySystemError):
    """Raised for database initialization, connection, or query failures."""


class AuthenticationError(USBSecuritySystemError):
    """Raised for login failures, lockouts, or invalid session state."""


class AuthorizationError(USBSecuritySystemError):
    """Raised when a user attempts an action their role does not permit."""


class USBDetectionError(USBSecuritySystemError):
    """Raised when the Windows USB monitoring subsystem fails to start or read a device."""


class DeviceFingerprintError(USBSecuritySystemError):
    """Raised when a device fingerprint cannot be computed from available metadata."""


class PolicyEvaluationError(USBSecuritySystemError):
    """Raised when the policy engine cannot evaluate a device against configured policies."""


class EnforcementError(USBSecuritySystemError):
    """
    Raised when an enforcement action (block/disable device) is attempted but
    fails. This is an expected, handled outcome (see EnforcementResult.BLOCKING_FAILED)
    and must never be silently swallowed or misreported as success.
    """


class InsufficientPrivilegesError(EnforcementError):
    """Raised when an enforcement or device-management action requires
    administrator privileges that the current process does not have."""


class ReportGenerationError(USBSecuritySystemError):
    """Raised when PDF/CSV report generation fails."""
