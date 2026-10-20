"""
Phase 6 GUI tests: the real Devices page wired to the repository, and
the full live pipeline through MainWindow - simulate a connection,
confirm the table and dashboard counts update, approve/block via the
UI, and confirm permission gating for Security Analysts.

Run with: pytest tests/test_phase6_gui.py -v
"""

import time

import pytest

from app.database.engine import get_engine, session_scope
from app.database.init_db import initialize_database
from app.database.models import User
from app.security.auth import AuthService
from app.security.bootstrap import create_initial_administrator
from app.security.password import hash_password
from app.devices import repository as device_repo
from ui.windows.main_window import MainWindow
from ui.windows.devices_page import DevicesPage


@pytest.fixture()
def test_engine(tmp_path):
    db_path = tmp_path / "test_phase6_gui.db"
    engine = get_engine(database_url=f"sqlite:///{db_path.as_posix()}")
    initialize_database(engine=engine)
    return engine


@pytest.fixture()
def admin_user(test_engine):
    return create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)


@pytest.fixture()
def analyst_user(test_engine):
    with session_scope(engine=test_engine) as session:
        session.add(User(username="analyst", password_hash=hash_password("Str0ngPassphrase!"), role="SECURITY_ANALYST"))


def _wait_until(predicate, timeout=2.0, interval=0.05):
    from PySide6.QtCore import QCoreApplication
    deadline = time.time() + timeout
    while time.time() < deadline:
        QCoreApplication.processEvents()
        if predicate():
            return True
        time.sleep(interval)
    QCoreApplication.processEvents()
    return predicate()


# --- DevicesPage in isolation -------------------------------------------------
def test_devices_page_lists_registered_devices(qtbot, test_engine, admin_user):
    from app.usb.device_info import USBDeviceInfo
    device_repo.record_device_event(
        USBDeviceInfo(event_type="CONNECTED", name="Test Drive", vendor_id="AAAA", product_id="BBBB", serial_number="123"),
        engine=test_engine,
    )
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    page = DevicesPage(user, engine=test_engine)
    qtbot.addWidget(page)
    assert page.table.rowCount() == 1
    assert page.table.item(0, 0).text() == "Test Drive"


def test_devices_page_approve_button_updates_status(qtbot, test_engine, admin_user):
    from app.usb.device_info import USBDeviceInfo
    device_repo.record_device_event(
        USBDeviceInfo(event_type="CONNECTED", name="Test Drive", vendor_id="AAAA", product_id="BBBB", serial_number="123"),
        engine=test_engine,
    )
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    page = DevicesPage(user, engine=test_engine)
    qtbot.addWidget(page)

    page.table.selectRow(0)
    page._approve_selected()

    devices = device_repo.list_devices(engine=test_engine)
    assert devices[0].status == "TRUSTED"
    assert page.table.item(0, 6).text() == "TRUSTED"


def test_devices_page_analyst_cannot_manage(qtbot, test_engine, analyst_user):
    from app.usb.device_info import USBDeviceInfo
    device_repo.record_device_event(
        USBDeviceInfo(event_type="CONNECTED", name="Test Drive", vendor_id="AAAA", product_id="BBBB", serial_number="123"),
        engine=test_engine,
    )
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("analyst", "Str0ngPassphrase!")
    page = DevicesPage(user, engine=test_engine)
    qtbot.addWidget(page)

    page.table.selectRow(0)
    # Buttons must be disabled for a Security Analyst (Section 6: read-only).
    assert page.approve_button.isEnabled() is False
    assert page.block_button.isEnabled() is False
    assert page.revoke_button.isEnabled() is False


def test_devices_page_filter_by_status(qtbot, test_engine, admin_user):
    from app.usb.device_info import USBDeviceInfo
    device_repo.record_device_event(
        USBDeviceInfo(event_type="CONNECTED", name="Drive A", vendor_id="AAAA", product_id="BBBB", serial_number="1"),
        engine=test_engine,
    )
    device_repo.record_device_event(
        USBDeviceInfo(event_type="CONNECTED", name="Drive B", vendor_id="CCCC", product_id="DDDD", serial_number="2"),
        engine=test_engine,
    )
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    page = DevicesPage(user, engine=test_engine)
    qtbot.addWidget(page)

    devices = device_repo.list_devices(engine=test_engine)
    device_repo.approve_device(devices[0].id, user.id, engine=test_engine)

    page._set_filter("TRUSTED")
    assert page.table.rowCount() == 1
    page._set_filter(None)
    assert page.table.rowCount() == 2


# --- full live pipeline via MainWindow -------------------------------------------------
def test_simulated_connection_flows_through_to_devices_table(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    window = MainWindow(auth, user, engine=test_engine)
    qtbot.addWidget(window)

    devices_page = window._pages["devices"]
    assert devices_page.table.rowCount() == 0

    window._usb_monitor.inject_connect("kingston_datatraveler")
    assert _wait_until(lambda: devices_page.table.rowCount() == 1)
    assert devices_page.table.item(0, 0).text() == "Kingston DataTraveler 3.0"


def test_simulated_connection_updates_dashboard_counts(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    window = MainWindow(auth, user, engine=test_engine)
    qtbot.addWidget(window)

    dashboard_page = window._pages["dashboard"]
    assert dashboard_page.total_devices_card.value_widget.text() == "0"

    window._usb_monitor.inject_connect("kingston_datatraveler")
    assert _wait_until(lambda: dashboard_page.total_devices_card.value_widget.text() == "1")


def test_main_window_stop_closes_monitor_cleanly(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    window = MainWindow(auth, user, engine=test_engine)
    qtbot.addWidget(window)
    assert window._usb_monitor.is_running is True
    window.close()
    assert window._usb_monitor.is_running is False
