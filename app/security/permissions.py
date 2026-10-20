"""
Role-based access control (Section 6).

Administrator: full access.
Security Analyst: read-only on dashboard/devices/alerts/audit logs, can
generate reports, but cannot create/modify/delete policies, manage
users, block/approve devices, or change system settings.
"""

from __future__ import annotations

from enum import Enum

from app.core.enums import UserRole
from app.core.exceptions import AuthorizationError


class Permission(str, Enum):
    VIEW_DASHBOARD = "VIEW_DASHBOARD"
    VIEW_DEVICES = "VIEW_DEVICES"
    REGISTER_TRUSTED_DEVICE = "REGISTER_TRUSTED_DEVICE"
    BLOCK_DEVICE = "BLOCK_DEVICE"
    REVOKE_DEVICE = "REVOKE_DEVICE"
    CREATE_POLICY = "CREATE_POLICY"
    MODIFY_POLICY = "MODIFY_POLICY"
    DELETE_POLICY = "DELETE_POLICY"
    VIEW_ALERTS = "VIEW_ALERTS"
    RESOLVE_ALERT = "RESOLVE_ALERT"
    VIEW_AUDIT_LOGS = "VIEW_AUDIT_LOGS"
    GENERATE_REPORTS = "GENERATE_REPORTS"
    MANAGE_USERS = "MANAGE_USERS"
    CONFIGURE_SETTINGS = "CONFIGURE_SETTINGS"


_ADMINISTRATOR_PERMISSIONS = set(Permission)  # everything

_SECURITY_ANALYST_PERMISSIONS = {
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_DEVICES,
    Permission.VIEW_ALERTS,
    Permission.VIEW_AUDIT_LOGS,
    Permission.GENERATE_REPORTS,
}

_ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    UserRole.ADMINISTRATOR.value: _ADMINISTRATOR_PERMISSIONS,
    UserRole.SECURITY_ANALYST.value: _SECURITY_ANALYST_PERMISSIONS,
}


def has_permission(role: str, permission: Permission) -> bool:
    return permission in _ROLE_PERMISSIONS.get(role, set())


def require_permission(role: str, permission: Permission) -> None:
    """Raise AuthorizationError if `role` does not grant `permission`."""
    if not has_permission(role, permission):
        raise AuthorizationError(
            f"Role '{role}' does not have permission '{permission.value}'."
        )
