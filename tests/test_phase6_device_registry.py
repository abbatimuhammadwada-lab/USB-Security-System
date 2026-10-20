"""
Phase 6 tests: the device registry repository - recording detected
events, deduplication via fingerprinting, approve/block/revoke actions,
temporary-authorization expiry, and query/count functions.

Run with: pytest tests/test_phase6_device_registry.py -v
"""

import datetime as dt

import pytest
from sqlalchemy import select

from app.core.enums import DeviceStatus, EnforcementResult
from app.database.engine import get_engine, session_scope
from app.database.init_db import initialize_database
from app.database.models import USBDevice, DeviceEvent, AuditLog
from app.devices.repository import (
    record_device_event, approve_device, block_device, revoke_device,
    authorize_temporary, list_devices, get_device, get_device_events,
    get_device_counts,
)
from app.security.bootstrap import create_initial_administrator
from app.usb.device_info import USBDeviceInfo
from app.usb.simulation_monitor import DEVICE_PROFILES


@pytest.fixture()
def test_engine(tmp_path):
    db_path = tmp_path / "test_devices.db"
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


def _remove_info(profile: str = "kingston_datatraveler", **overrides) -> USBDeviceInfo:
    fields = dict(DEVICE_PROFILES[profile])
    fields.update(overrides)
    return USBDeviceInfo(event_type="REMOVED", is_simulated=True, computer_name="TEST-PC", **fields)


# --- recording events -------------------------------------------------
def test_new_device_recorded_as_unknown(test_engine):
    record_device_event(_connect_info(), engine=test_engine)
    devices = list_devices(engine=test_engine)
    assert len(devices) == 1
    assert devices[0].status == DeviceStatus.UNKNOWN.value
    assert devices[0].name == "Kingston DataTraveler 3.0"


def test_event_result_is_detected_not_a_policy_decision(test_engine):
    """Phase 6 must not pre-empt Phase 7's policy engine - a fresh
    connection event records DETECTED, never AUTHORIZED/UNAUTHORIZED."""
    event = record_device_event(_connect_info(), engine=test_engine)
    assert event.result == EnforcementResult.DETECTED.value


def test_same_physical_device_does_not_duplicate(test_engine):
    record_device_event(_connect_info(), engine=test_engine)
    record_device_event(_remove_info(), engine=test_engine)
    record_device_event(_connect_info(), engine=test_engine)

    devices = list_devices(engine=test_engine)
    assert len(devices) == 1
    assert devices[0].connection_count == 2


def test_different_devices_create_separate_registry_entries(test_engine):
    record_device_event(_connect_info("kingston_datatraveler"), engine=test_engine)
    record_device_event(_connect_info("logitech_mouse"), engine=test_engine)
    devices = list_devices(engine=test_engine)
    assert len(devices) == 2


def test_remove_event_recorded_with_removed_result(test_engine):
    record_device_event(_connect_info(), engine=test_engine)
    event = record_device_event(_remove_info(), engine=test_engine)
    assert event.result == EnforcementResult.REMOVED.value
    assert event.event_type == "REMOVED"


def test_unfingerprintable_device_does_not_crash(test_engine):
    info = USBDeviceInfo(event_type="CONNECTED", is_simulated=True)  # zero identity
    result = record_device_event(info, engine=test_engine)
    assert result is None  # handled gracefully, not raised

    with session_scope(engine=test_engine) as session:
        logs = session.scalars(select(AuditLog)).all()
        assert any("could not be fingerprinted" in log.description for log in logs)


def test_event_history_recorded_per_device(test_engine):
    record_device_event(_connect_info(), engine=test_engine)
    record_device_event(_remove_info(), engine=test_engine)
    record_device_event(_connect_info(), engine=test_engine)

    devices = list_devices(engine=test_engine)
    events = get_device_events(devices[0].id, engine=test_engine)
    assert len(events) == 3
    assert events[0].timestamp >= events[-1].timestamp  # newest first


# --- approve / block / revoke -------------------------------------------------
def test_approve_device_sets_trusted(test_engine, admin):
    record_device_event(_connect_info(), engine=test_engine)
    device = list_devices(engine=test_engine)[0]

    updated = approve_device(device.id, admin.id, engine=test_engine)
    assert updated.status == DeviceStatus.TRUSTED.value
    assert updated.approved_by == admin.id
    assert updated.approved_at is not None


def test_block_device_sets_blocked(test_engine, admin):
    record_device_event(_connect_info(), engine=test_engine)
    device = list_devices(engine=test_engine)[0]

    updated = block_device(device.id, admin.id, engine=test_engine)
    assert updated.status == DeviceStatus.BLOCKED.value


def test_revoke_device_resets_to_unknown(test_engine, admin):
    record_device_event(_connect_info(), engine=test_engine)
    device = list_devices(engine=test_engine)[0]
    approve_device(device.id, admin.id, engine=test_engine)

    updated = revoke_device(device.id, admin.id, engine=test_engine)
    assert updated.status == DeviceStatus.UNKNOWN.value
    assert updated.approved_by is None
    assert updated.approved_at is None


def test_reconnect_after_approval_reflects_trusted_status(test_engine, admin):
    """Section 27 scenario 9-11: approve, then reconnect, and the device
    is recognized as authorized (its registry status is TRUSTED)."""
    record_device_event(_connect_info(), engine=test_engine)
    device = list_devices(engine=test_engine)[0]
    approve_device(device.id, admin.id, engine=test_engine)

    record_device_event(_connect_info(), engine=test_engine)  # reconnect
    device_after = get_device(device.id, engine=test_engine)
    assert device_after.status == DeviceStatus.TRUSTED.value
    assert device_after.connection_count == 2


def test_actions_write_distinct_audit_events(test_engine, admin):
    record_device_event(_connect_info(), engine=test_engine)
    device = list_devices(engine=test_engine)[0]
    approve_device(device.id, admin.id, engine=test_engine)
    block_device(device.id, admin.id, engine=test_engine)
    revoke_device(device.id, admin.id, engine=test_engine)

    with session_scope(engine=test_engine) as session:
        event_types = [log.event_type for log in session.scalars(select(AuditLog)).all()]
        assert "DEVICE_APPROVED" in event_types
        assert "DEVICE_BLOCKED" in event_types
        assert "DEVICE_REVOKED" in event_types


def test_approve_unknown_device_id_raises(test_engine, admin):
    with pytest.raises(ValueError):
        approve_device(9999, admin.id, engine=test_engine)


# --- temporary authorization -------------------------------------------------
def test_authorize_temporary_sets_expiry(test_engine, admin):
    record_device_event(_connect_info(), engine=test_engine)
    device = list_devices(engine=test_engine)[0]
    expires_at = dt.datetime.utcnow() + dt.timedelta(hours=2)

    updated = authorize_temporary(device.id, admin.id, expires_at, engine=test_engine)
    assert updated.status == DeviceStatus.TEMPORARY.value
    assert updated.temporary_expires_at is not None


def test_authorize_temporary_rejects_past_expiry(test_engine, admin):
    record_device_event(_connect_info(), engine=test_engine)
    device = list_devices(engine=test_engine)[0]
    past = dt.datetime.utcnow() - dt.timedelta(hours=1)
    with pytest.raises(ValueError):
        authorize_temporary(device.id, admin.id, past, engine=test_engine)


def test_expired_temporary_authorization_reverts_on_next_connection(test_engine, admin):
    record_device_event(_connect_info(), engine=test_engine)
    device = list_devices(engine=test_engine)[0]

    # Authorize temporarily, then manually force it into the past to
    # simulate time passing (avoids a real sleep in the test suite).
    future = dt.datetime.utcnow() + dt.timedelta(seconds=1)
    authorize_temporary(device.id, admin.id, future, engine=test_engine)
    with session_scope(engine=test_engine) as session:
        row = session.get(USBDevice, device.id)
        row.temporary_expires_at = dt.datetime.utcnow() - dt.timedelta(minutes=1)

    record_device_event(_connect_info(), engine=test_engine)  # reconnect triggers the expiry check
    device_after = get_device(device.id, engine=test_engine)
    assert device_after.status == DeviceStatus.UNKNOWN.value
    assert device_after.temporary_expires_at is None


# --- queries / counts -------------------------------------------------
def test_list_devices_filters_by_status(test_engine, admin):
    record_device_event(_connect_info("kingston_datatraveler"), engine=test_engine)
    record_device_event(_connect_info("logitech_mouse"), engine=test_engine)
    devices = list_devices(engine=test_engine)
    approve_device(devices[0].id, admin.id, engine=test_engine)

    trusted = list_devices(status_filter=DeviceStatus.TRUSTED.value, engine=test_engine)
    unknown = list_devices(status_filter=DeviceStatus.UNKNOWN.value, engine=test_engine)
    assert len(trusted) == 1
    assert len(unknown) == 1


def test_device_counts_reflect_registry_state(test_engine, admin):
    record_device_event(_connect_info("kingston_datatraveler"), engine=test_engine)
    record_device_event(_connect_info("logitech_mouse"), engine=test_engine)
    record_device_event(_connect_info("unknown_no_serial"), engine=test_engine)
    devices = list_devices(engine=test_engine)
    approve_device(devices[0].id, admin.id, engine=test_engine)
    block_device(devices[1].id, admin.id, engine=test_engine)

    counts = get_device_counts(engine=test_engine)
    assert counts.total == 3
    assert counts.trusted == 1
    assert counts.blocked == 1
    assert counts.unknown == 1


def test_get_device_returns_none_for_missing_id(test_engine):
    assert get_device(12345, engine=test_engine) is None
