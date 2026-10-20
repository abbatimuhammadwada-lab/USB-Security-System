"""
Phase 7 tests: condition matching, policy CRUD, evaluation ordering,
default-deny fallback, enforcement (non-Windows behavior), and the
full connection pipeline.

Run with: pytest tests/test_phase7_policy_engine.py -v
"""

import datetime as dt

import pytest
from sqlalchemy import select

from app.core.enums import PolicyAction, PolicyStatus, EnforcementResult, DeviceStatus
from app.core.exceptions import PolicyEvaluationError
from app.database.engine import get_engine, session_scope
from app.database.init_db import initialize_database
from app.database.models import AuditLog
from app.enforcement.windows_enforcement import attempt_block_device
from app.policy.conditions import matches, validate_conditions_schema
from app.policy.engine import evaluate
from app.policy.pipeline import process_connection_event
from app.policy.repository import create_policy, update_policy, delete_policy, list_policies, get_policy
from app.security.bootstrap import create_initial_administrator
from app.devices import repository as device_repo
from app.usb.device_info import USBDeviceInfo
from app.usb.simulation_monitor import DEVICE_PROFILES


@pytest.fixture()
def test_engine(tmp_path):
    db_path = tmp_path / "test_policy.db"
    engine = get_engine(database_url=f"sqlite:///{db_path.as_posix()}")
    initialize_database(engine=engine)
    return engine


@pytest.fixture()
def admin(test_engine):
    return create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)


def _connect_info(profile: str = "kingston_datatraveler", **overrides) -> USBDeviceInfo:
    fields = dict(DEVICE_PROFILES[profile])
    fields.update(overrides)
    return USBDeviceInfo(event_type="CONNECTED", is_simulated=True, computer_name="TEST-PC", **fields)


# --- condition matching -------------------------------------------------
def test_empty_conditions_match_everything():
    assert matches({}, {"device_status": "TRUSTED"}) is True


def test_list_condition_matches_case_insensitively():
    assert matches({"device_status": ["Trusted"]}, {"device_status": "TRUSTED"}) is True


def test_list_condition_rejects_non_matching_value():
    assert matches({"device_status": ["BLOCKED"]}, {"device_status": "TRUSTED"}) is False


def test_unknown_condition_key_raises():
    with pytest.raises(PolicyEvaluationError):
        matches({"not_a_real_key": ["x"]}, {})


def test_malformed_list_condition_raises():
    with pytest.raises(PolicyEvaluationError):
        matches({"device_status": "TRUSTED"}, {"device_status": "TRUSTED"})  # should be a list


def test_time_window_same_day():
    now = dt.datetime(2026, 1, 1, 10, 0)
    assert matches({"time_window": {"start": "08:00", "end": "18:00"}}, {}, now=now) is True
    now_outside = dt.datetime(2026, 1, 1, 22, 0)
    assert matches({"time_window": {"start": "08:00", "end": "18:00"}}, {}, now=now_outside) is False


def test_time_window_overnight_wrap():
    late_night = dt.datetime(2026, 1, 1, 23, 0)
    early_morning = dt.datetime(2026, 1, 1, 5, 0)
    midday = dt.datetime(2026, 1, 1, 12, 0)
    cond = {"time_window": {"start": "18:00", "end": "08:00"}}
    assert matches(cond, {}, now=late_night) is True
    assert matches(cond, {}, now=early_morning) is True
    assert matches(cond, {}, now=midday) is False


def test_validate_conditions_schema_raises_on_bad_input():
    with pytest.raises(PolicyEvaluationError):
        validate_conditions_schema({"time_window": {"start": "not-a-time", "end": "08:00"}})


def test_validate_conditions_schema_passes_valid_input():
    validate_conditions_schema({"device_status": ["TRUSTED"]})  # must not raise


# --- default seeded policies -------------------------------------------------
def test_default_policies_seeded(test_engine):
    policies = list_policies(engine=test_engine)
    names = {p.name for p in policies}
    assert "Allow trusted devices" in names
    assert "Block blacklisted devices" in names
    assert "Block unknown devices by default" in names


def test_default_policies_in_priority_order(test_engine):
    policies = list_policies(engine=test_engine)
    priorities = [p.priority for p in policies]
    assert priorities == sorted(priorities)


def test_seeding_is_idempotent_and_preserves_customization(test_engine, admin):
    # Delete one default and add a custom one; re-running init must not
    # resurrect the deleted default or duplicate anything.
    policies = list_policies(engine=test_engine)
    delete_policy(policies[0].id, admin.id, engine=test_engine)
    create_policy("Custom policy", PolicyAction.LOG_ONLY.value, admin.id, engine=test_engine)

    initialize_database(engine=test_engine)  # re-run

    policies_after = list_policies(engine=test_engine)
    names_after = {p.name for p in policies_after}
    assert "Custom policy" in names_after
    assert len(policies_after) == 3  # 2 remaining defaults + 1 custom, no resurrection/duplication


# --- policy CRUD -------------------------------------------------
def test_create_policy_writes_audit_log(test_engine, admin):
    create_policy("Test Policy", PolicyAction.ALERT.value, admin.id, priority=5, engine=test_engine)
    with session_scope(engine=test_engine) as session:
        logs = session.scalars(select(AuditLog)).all()
        assert any(log.event_type == "POLICY_CREATED" for log in logs)


def test_create_policy_rejects_malformed_conditions(test_engine, admin):
    with pytest.raises(PolicyEvaluationError):
        create_policy(
            "Bad Policy", PolicyAction.BLOCK.value, admin.id,
            conditions={"time_window": {"start": "bad", "end": "08:00"}}, engine=test_engine,
        )


def test_update_policy_changes_fields_and_audits(test_engine, admin):
    policy = create_policy("Editable", PolicyAction.LOG_ONLY.value, admin.id, priority=50, engine=test_engine)
    updated = update_policy(policy.id, admin.id, priority=5, action=PolicyAction.ALERT.value, engine=test_engine)
    assert updated.priority == 5
    assert updated.action == PolicyAction.ALERT.value

    with session_scope(engine=test_engine) as session:
        logs = session.scalars(select(AuditLog)).all()
        assert any(log.event_type == "POLICY_CHANGED" for log in logs)


def test_delete_policy_removes_it_and_audits(test_engine, admin):
    policy = create_policy("Temp", PolicyAction.LOG_ONLY.value, admin.id, engine=test_engine)
    delete_policy(policy.id, admin.id, engine=test_engine)
    assert get_policy(policy.id, engine=test_engine) is None

    with session_scope(engine=test_engine) as session:
        logs = session.scalars(select(AuditLog)).all()
        assert any(log.event_type == "POLICY_DELETED" for log in logs)


def test_update_missing_policy_raises_value_error(test_engine, admin):
    with pytest.raises(ValueError):
        update_policy(99999, admin.id, priority=1, engine=test_engine)


# --- evaluation ordering -------------------------------------------------
def test_higher_priority_custom_policy_overrides_default(test_engine, admin):
    """A lower-numbered (higher priority) custom policy must be
    evaluated before the seeded 'block unknown' default."""
    create_policy(
        "VIP override", PolicyAction.ALLOW.value, admin.id, priority=1,
        conditions={"vendor_id": ["0951"]}, engine=test_engine,
    )
    context = {"device_status": "UNKNOWN", "vendor_id": "0951"}
    decision = evaluate(context, engine=test_engine)
    assert decision.action == PolicyAction.ALLOW.value
    assert decision.matched_policy_name == "VIP override"


def test_unknown_device_blocked_by_default_policy(test_engine):
    decision = evaluate({"device_status": "UNKNOWN"}, engine=test_engine)
    assert decision.action == PolicyAction.BLOCK.value
    assert decision.matched_policy_name == "Block unknown devices by default"


def test_trusted_device_allowed(test_engine):
    decision = evaluate({"device_status": "TRUSTED"}, engine=test_engine)
    assert decision.action == PolicyAction.ALLOW.value


def test_blocked_device_blocked(test_engine):
    decision = evaluate({"device_status": "BLOCKED"}, engine=test_engine)
    assert decision.action == PolicyAction.BLOCK.value
    assert decision.matched_policy_name == "Block blacklisted devices"


def test_fail_closed_when_no_policies_match_anything(test_engine, admin):
    for p in list_policies(engine=test_engine):
        delete_policy(p.id, admin.id, engine=test_engine)
    decision = evaluate({"device_status": "TRUSTED"}, engine=test_engine)
    assert decision.action == PolicyAction.BLOCK.value
    assert decision.matched_policy_id is None
    assert "default-deny" in decision.reason.lower()


def test_disabled_policy_is_not_evaluated(test_engine, admin):
    policy = create_policy(
        "Disabled allow-all", PolicyAction.ALLOW.value, admin.id, priority=1,
        status=PolicyStatus.DISABLED.value, engine=test_engine,
    )
    decision = evaluate({"device_status": "UNKNOWN"}, engine=test_engine)
    assert decision.action == PolicyAction.BLOCK.value  # falls through to the default, not the disabled ALLOW


def test_malformed_policy_is_skipped_not_fatal(test_engine, admin):
    """A policy with conditions that fail validation at evaluation time
    (bypassing create-time validation via direct update) must be
    skipped, not crash evaluation for every device."""
    from app.database.models import Policy
    with session_scope(engine=test_engine) as session:
        bad = Policy(name="Corrupt", priority=1, conditions='{"time_window": {"start": "bad"}}',
                     action=PolicyAction.ALLOW.value, status=PolicyStatus.ACTIVE.value)
        session.add(bad)

    decision = evaluate({"device_status": "UNKNOWN"}, engine=test_engine)
    assert decision.action == PolicyAction.BLOCK.value  # still reaches the valid default policy


# --- enforcement (non-Windows honesty) -------------------------------------------------
def test_enforcement_fails_gracefully_without_pnp_id():
    outcome = attempt_block_device(None)
    assert outcome.result == EnforcementResult.BLOCKING_FAILED.value


def test_enforcement_fails_gracefully_on_non_windows():
    from app.config import settings as settings_module
    if settings_module.settings.is_windows:
        pytest.skip("This test only applies on non-Windows platforms.")
    outcome = attempt_block_device(r"USBSTOR\DISK&VEN_TEST\INSTANCE1")
    assert outcome.result == EnforcementResult.BLOCKING_FAILED.value
    assert "windows" in outcome.reason.lower()


# --- full pipeline -------------------------------------------------
def test_pipeline_allows_trusted_device(test_engine, admin):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    device_repo.approve_device(device.id, admin.id, engine=test_engine)

    outcome = process_connection_event(_connect_info(), engine=test_engine)
    assert outcome.decision.action == PolicyAction.ALLOW.value
    assert outcome.final_result == EnforcementResult.ALLOWED.value


def test_pipeline_blocks_unknown_device_fails_enforcement_gracefully(test_engine):
    """On this non-Windows/non-admin sandbox, BLOCK decisions must
    result in BLOCKING_FAILED (attempted, not silently pretended)."""
    outcome = process_connection_event(_connect_info("unknown_no_serial"), engine=test_engine)
    assert outcome.decision.action == PolicyAction.BLOCK.value
    assert outcome.final_result == EnforcementResult.BLOCKING_FAILED.value


def test_pipeline_writes_access_denied_audit_for_block(test_engine):
    process_connection_event(_connect_info("unknown_no_serial"), engine=test_engine)
    with session_scope(engine=test_engine) as session:
        logs = session.scalars(select(AuditLog)).all()
        assert any(log.event_type == "ACCESS_DENIED" for log in logs)


def test_pipeline_removed_event_skips_policy_evaluation(test_engine):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    outcome = process_connection_event(
        USBDeviceInfo(event_type="REMOVED", is_simulated=True, **DEVICE_PROFILES["kingston_datatraveler"]),
        engine=test_engine,
    )
    assert outcome.decision is None
    assert outcome.final_result == EnforcementResult.REMOVED.value


def test_pipeline_reflects_result_on_device_event_row(test_engine, admin):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    device_repo.approve_device(device.id, admin.id, engine=test_engine)

    outcome = process_connection_event(_connect_info(), engine=test_engine)
    events = device_repo.get_device_events(device.id, engine=test_engine)
    latest = events[0]  # newest first
    assert latest.result == EnforcementResult.ALLOWED.value
