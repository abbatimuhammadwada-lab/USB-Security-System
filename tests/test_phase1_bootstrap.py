"""
Phase 1 smoke tests: configuration loads, directories are created,
and enums/exceptions are importable and well-formed.

Run with: pytest tests/test_phase1_bootstrap.py -v
"""

from app.config.settings import settings
from app.core.app_context import AppContext
from app.core.enums import (
    EnforcementResult,
    DeviceStatus,
    AlertSeverity,
    UserRole,
    PolicyAction,
)
from app.core.exceptions import USBSecuritySystemError, EnforcementError
from app.utils.privileges import is_running_as_admin


def test_settings_load():
    assert settings.app_short_name == "USB Security System"
    assert settings.database_url.startswith("sqlite:///")


def test_directories_exist():
    assert settings.data_dir.exists()
    assert settings.logs_dir.exists()
    assert settings.reports_dir.exists()


def test_app_context_constructs():
    ctx = AppContext()
    assert isinstance(ctx.is_admin_privileged, bool)
    assert isinstance(ctx.simulation_mode, bool)


def test_enforcement_result_values_match_spec():
    # These exact string values are what Section 4 requires the UI to show.
    expected = {
        "DETECTED", "AUTHORIZED", "UNAUTHORIZED", "BLOCKED",
        "ALLOWED", "BLOCKING_FAILED", "REMOVED", "UNKNOWN",
    }
    actual = {member.value for member in EnforcementResult}
    assert actual == expected


def test_exception_hierarchy():
    assert issubclass(EnforcementError, USBSecuritySystemError)


def test_privilege_check_returns_bool():
    assert isinstance(is_running_as_admin(), bool)


def test_user_role_values():
    assert {r.value for r in UserRole} == {"ADMINISTRATOR", "SECURITY_ANALYST"}


def test_policy_action_values():
    assert {a.value for a in PolicyAction} == {"ALLOW", "BLOCK", "ALERT", "LOG_ONLY"}
