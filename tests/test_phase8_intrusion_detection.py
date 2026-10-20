"""
Phase 8/9 tests: rule-based intrusion detection signals and their
persistence as security alerts.

Run with: pytest tests/test_phase8_intrusion_detection.py -v
"""

import datetime as dt

import pytest
from sqlalchemy import select

from app.core.enums import AlertType
from app.database.engine import get_engine, session_scope
from app.database.init_db import initialize_database
from app.database.models import SystemSetting
from app.detection.engine import analyze_connection
from app.detection.rules import (
    check_unknown_device, check_blacklisted_device, check_repeated_unauthorized_attempts,
    check_rapid_connect_disconnect, check_after_hours,
)
from app.devices import repository as device_repo
from app.alerts import repository as alert_repo
from app.policy.pipeline import process_connection_event
from app.security.bootstrap import create_initial_administrator
from app.usb.device_info import USBDeviceInfo
from app.usb.simulation_monitor import DEVICE_PROFILES


@pytest.fixture()
def test_engine(tmp_path):
    db_path = tmp_path / "test_ids.db"
    engine = get_engine(database_url=f"sqlite:///{db_path.as_posix()}")
    initialize_database(engine=engine)
    return engine


@pytest.fixture()
def admin(test_engine):
    return create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)


def _connect_info(profile="kingston_datatraveler", **overrides):
    fields = dict(DEVICE_PROFILES[profile])
    fields.update(overrides)
    return USBDeviceInfo(event_type="CONNECTED", is_simulated=True, computer_name="TEST-PC", **fields)


# --- individual rules -------------------------------------------------
def test_unknown_device_signal(test_engine):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    signal = check_unknown_device(device)
    assert signal is not None
    assert signal.alert_type == AlertType.UNKNOWN_USB.value


def test_trusted_device_no_unknown_signal(test_engine, admin):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    device_repo.approve_device(device.id, admin.id, engine=test_engine)
    device = device_repo.get_device(device.id, engine=test_engine)
    assert check_unknown_device(device) is None


def test_blacklisted_device_signal(test_engine, admin):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    device_repo.block_device(device.id, admin.id, engine=test_engine)
    device = device_repo.get_device(device.id, engine=test_engine)
    signal = check_blacklisted_device(device)
    assert signal is not None
    assert signal.alert_type == AlertType.BLACKLISTED_USB.value


def test_repeated_unauthorized_attempts_below_threshold(test_engine):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    signal = check_repeated_unauthorized_attempts(device.id, engine=test_engine, threshold=5, window_minutes=10)
    assert signal is None  # only 1 event so far (DETECTED, not unauthorized anyway)


def test_repeated_unauthorized_attempts_triggers_at_threshold(test_engine):
    from app.database.models import DeviceEvent
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]

    now = dt.datetime.utcnow()
    with session_scope(engine=test_engine) as session:
        for _ in range(5):
            session.add(DeviceEvent(
                device_id=device.id, event_type="CONNECTED", result="UNAUTHORIZED",
                is_simulated=True, timestamp=now,
            ))

    signal = check_repeated_unauthorized_attempts(device.id, engine=test_engine, threshold=5, window_minutes=10, now=now)
    assert signal is not None
    assert signal.alert_type == AlertType.REPEATED_UNAUTHORIZED_ATTEMPTS.value


def test_repeated_unauthorized_attempts_outside_window_not_counted(test_engine):
    from app.database.models import DeviceEvent
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]

    old_time = dt.datetime.utcnow() - dt.timedelta(hours=2)
    with session_scope(engine=test_engine) as session:
        for _ in range(5):
            session.add(DeviceEvent(
                device_id=device.id, event_type="CONNECTED", result="UNAUTHORIZED",
                is_simulated=True, timestamp=old_time,
            ))

    signal = check_repeated_unauthorized_attempts(
        device.id, engine=test_engine, threshold=5, window_minutes=10, now=dt.datetime.utcnow()
    )
    assert signal is None


def test_rapid_connect_disconnect_triggers(test_engine):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    now = dt.datetime.utcnow()

    for _ in range(3):
        device_repo.record_device_event(_connect_info(), engine=test_engine)

    signal = check_rapid_connect_disconnect(device.id, engine=test_engine, window_seconds=60, cycle_threshold=3, now=now)
    assert signal is not None
    assert signal.alert_type == AlertType.RAPID_CONNECT_DISCONNECT.value


def test_after_hours_detected(test_engine):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    late_night = dt.datetime(2026, 1, 1, 23, 30)  # business hours default 08:00-18:00
    signal = check_after_hours(device, late_night, engine=test_engine)
    assert signal is not None
    assert signal.alert_type == AlertType.AFTER_HOURS_CONNECTION.value


def test_within_business_hours_not_flagged(test_engine):
    device_repo.record_device_event(_connect_info(), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    midday = dt.datetime(2026, 1, 1, 12, 0)
    assert check_after_hours(device, midday, engine=test_engine) is None


# --- full pipeline -> alert persistence -------------------------------------------------
def test_pipeline_persists_alert_for_unknown_device(test_engine):
    process_connection_event(_connect_info(), engine=test_engine)
    alerts = alert_repo.list_alerts(engine=test_engine)
    types = {a.alert_type for a in alerts}
    assert AlertType.UNKNOWN_USB.value in types
    assert AlertType.POLICY_VIOLATION.value in types  # unknown -> default-deny -> policy violation too


def test_pipeline_no_alerts_for_trusted_device(test_engine, admin):
    """A trusted device reconnecting during business hours, with a clean
    history, should not trigger unknown/blacklisted/policy-violation
    signals. (After-hours and rapid-reconnect are independent checks -
    controlled for explicitly here rather than left to wall-clock time.)"""
    midday = dt.datetime(2026, 1, 1, 12, 0)
    device_repo.record_device_event(_connect_info(timestamp=midday), engine=test_engine)
    device = device_repo.list_devices(engine=test_engine)[0]
    device_repo.approve_device(device.id, admin.id, engine=test_engine)

    # Clear alerts generated by the first (unknown) connection before approval.
    with session_scope(engine=test_engine) as session:
        from app.database.models import SecurityAlert
        session.query(SecurityAlert).delete()

    process_connection_event(
        _connect_info(timestamp=midday + dt.timedelta(hours=1)), engine=test_engine
    )  # reconnect an hour later, now trusted
    alerts = alert_repo.list_alerts(engine=test_engine)
    assert len(alerts) == 0


def test_alert_mark_resolved(test_engine, admin):
    process_connection_event(_connect_info(), engine=test_engine)
    alerts = alert_repo.list_alerts(engine=test_engine)
    assert len(alerts) > 0

    resolved = alert_repo.mark_resolved(alerts[0].id, admin.id, engine=test_engine)
    assert resolved.is_resolved is True
    assert resolved.resolved_by == admin.id


def test_alert_counts(test_engine):
    process_connection_event(_connect_info(), engine=test_engine)
    counts = alert_repo.get_alert_counts(engine=test_engine)
    assert counts["total"] > 0
    assert counts["unresolved"] == counts["total"]


def test_filter_alerts_by_severity(test_engine):
    process_connection_event(_connect_info(), engine=test_engine)
    high_alerts = alert_repo.list_alerts(severity="HIGH", engine=test_engine)
    for a in high_alerts:
        assert a.severity == "HIGH"
