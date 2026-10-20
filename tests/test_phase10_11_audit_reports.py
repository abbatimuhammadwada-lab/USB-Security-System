"""
Phase 10 (audit log search) and Phase 11 (report generation) tests.

Run with: pytest tests/test_phase10_11_audit_reports.py -v
"""

import datetime as dt

import pytest

from app.database.engine import get_engine
from app.database.init_db import initialize_database
from app.logging.query import search_audit_logs, distinct_event_types
from app.policy.pipeline import process_connection_event
from app.reports import data as report_data
from app.reports import pdf_export, csv_export
from app.security.bootstrap import create_initial_administrator
from app.usb.device_info import USBDeviceInfo
from app.usb.simulation_monitor import DEVICE_PROFILES


@pytest.fixture()
def test_engine(tmp_path):
    db_path = tmp_path / "test_reports.db"
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


# --- audit log search -------------------------------------------------
def test_search_audit_logs_returns_results(test_engine, admin):
    process_connection_event(_connect_info(), engine=test_engine)
    logs = search_audit_logs(engine=test_engine)
    assert len(logs) > 0


def test_search_audit_logs_filters_by_event_type(test_engine, admin):
    process_connection_event(_connect_info(), engine=test_engine)
    logs = search_audit_logs(event_type="USB_CONNECTED", engine=test_engine)
    assert all(log.event_type == "USB_CONNECTED" for log in logs)
    assert len(logs) > 0


def test_search_audit_logs_username_resolved(test_engine, admin):
    from app.security.auth import AuthService
    auth = AuthService(engine=test_engine)
    auth.authenticate("admin", "Str0ngPassphrase!")
    logs = search_audit_logs(event_type="LOGIN", engine=test_engine)
    assert logs[0].username == "admin"


def test_distinct_event_types_nonempty(test_engine, admin):
    process_connection_event(_connect_info(), engine=test_engine)
    types = distinct_event_types(engine=test_engine)
    assert "USB_CONNECTED" in types


def test_search_audit_logs_date_range_filter(test_engine, admin):
    process_connection_event(_connect_info(), engine=test_engine)
    future_start = dt.datetime.utcnow() + dt.timedelta(days=1)
    logs = search_audit_logs(start=future_start, engine=test_engine)
    assert len(logs) == 0


# --- report data assembly -------------------------------------------------
def test_usb_activity_report_has_rows(test_engine, admin):
    process_connection_event(_connect_info(), engine=test_engine)
    rows = report_data.build_usb_activity_report(engine=test_engine)
    assert len(rows) > 0
    assert rows[0].device_name == "Kingston DataTraveler 3.0"


def test_security_incident_report_has_rows(test_engine, admin):
    process_connection_event(_connect_info(), engine=test_engine)  # unknown device -> alerts
    rows = report_data.build_security_incident_report(engine=test_engine)
    assert len(rows) > 0


def test_device_inventory_report_groups_by_status(test_engine, admin):
    from app.devices import repository as device_repo
    process_connection_event(_connect_info(), engine=test_engine)
    devices = device_repo.list_devices(engine=test_engine)
    device_repo.approve_device(devices[0].id, admin.id, engine=test_engine)

    inventory = report_data.build_device_inventory_report(engine=test_engine)
    assert len(inventory.trusted) == 1
    assert len(inventory.unknown) == 0


# --- CSV export -------------------------------------------------
def test_export_usb_activity_csv(test_engine, admin, tmp_path):
    process_connection_event(_connect_info(), engine=test_engine)
    rows = report_data.build_usb_activity_report(engine=test_engine)
    path = tmp_path / "activity.csv"
    result_path = csv_export.export_usb_activity_csv(rows, path)
    assert result_path.exists()
    content = result_path.read_text()
    assert "Kingston DataTraveler" in content


def test_export_empty_report_csv_does_not_crash(tmp_path):
    path = tmp_path / "empty.csv"
    csv_export.export_usb_activity_csv([], path)
    assert path.exists()


# --- PDF export -------------------------------------------------
def test_export_usb_activity_pdf(test_engine, admin, tmp_path):
    process_connection_event(_connect_info(), engine=test_engine)
    rows = report_data.build_usb_activity_report(engine=test_engine)
    path = tmp_path / "activity.pdf"
    result_path = pdf_export.export_usb_activity_pdf(rows, path)
    assert result_path.exists()
    assert result_path.stat().st_size > 0
    with open(result_path, "rb") as f:
        assert f.read(4) == b"%PDF"  # real PDF file signature


def test_export_security_incident_pdf(test_engine, admin, tmp_path):
    process_connection_event(_connect_info(), engine=test_engine)
    rows = report_data.build_security_incident_report(engine=test_engine)
    path = tmp_path / "incident.pdf"
    pdf_export.export_security_incident_pdf(rows, path)
    assert path.exists()


def test_export_device_inventory_pdf(test_engine, admin, tmp_path):
    process_connection_event(_connect_info(), engine=test_engine)
    inventory = report_data.build_device_inventory_report(engine=test_engine)
    path = tmp_path / "inventory.pdf"
    pdf_export.export_device_inventory_pdf(inventory, path)
    assert path.exists()


def test_export_empty_pdf_does_not_crash(tmp_path):
    path = tmp_path / "empty.pdf"
    pdf_export.export_usb_activity_pdf([], path)
    assert path.exists()
