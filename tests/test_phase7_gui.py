"""
Phase 7 GUI tests: the real Policies page, and the full live pipeline
(simulate connect -> policy evaluated -> event result reflects the
decision) through MainWindow.

Run with: pytest tests/test_phase7_gui.py -v
"""

import time

import pytest
from PySide6.QtCore import QCoreApplication

from app.database.engine import get_engine, session_scope
from app.database.init_db import initialize_database
from app.database.models import User
from app.security.auth import AuthService
from app.security.bootstrap import create_initial_administrator
from app.security.password import hash_password
from app.devices import repository as device_repo
from ui.windows.main_window import MainWindow
from ui.windows.policies_page import PoliciesPage
from ui.windows.policy_edit_dialog import PolicyEditDialog


@pytest.fixture()
def test_engine(tmp_path):
    db_path = tmp_path / "test_phase7_gui.db"
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


def _pump(seconds=0.5):
    end = time.time() + seconds
    while time.time() < end:
        QCoreApplication.processEvents()
        time.sleep(0.02)


def _wait_until(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        QCoreApplication.processEvents()
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


# --- PoliciesPage -------------------------------------------------
def test_policies_page_lists_seeded_defaults(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    page = PoliciesPage(user, engine=test_engine)
    qtbot.addWidget(page)
    assert page.table.rowCount() == 3


def test_policies_page_analyst_has_no_management_buttons(qtbot, test_engine, analyst_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("analyst", "Str0ngPassphrase!")
    page = PoliciesPage(user, engine=test_engine)
    qtbot.addWidget(page)
    assert page.edit_button is None
    assert page.delete_button is None


def test_policies_page_admin_can_create_policy(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    page = PoliciesPage(user, engine=test_engine)
    qtbot.addWidget(page)

    dialog = PolicyEditDialog(parent=page)
    qtbot.addWidget(dialog)
    dialog.name_input.setText("Test GUI Policy")
    dialog.action_combo.setCurrentText("LOG_ONLY")
    values = dialog.get_values()
    assert values["name"] == "Test GUI Policy"

    from app.policy import repository as policy_repo
    policy_repo.create_policy(
        values["name"], values["action"], user.id,
        description=values["description"], priority=values["priority"],
        conditions=values["conditions"], status=values["status"], engine=test_engine,
    )
    page.refresh()
    assert page.table.rowCount() == 4


def test_policies_page_delete_removes_row(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    page = PoliciesPage(user, engine=test_engine)
    qtbot.addWidget(page)

    from app.policy import repository as policy_repo
    policy_repo.delete_policy(page._policies[0].id, user.id, engine=test_engine)
    page.refresh()
    assert page.table.rowCount() == 2


# --- full live pipeline via MainWindow -------------------------------------------------
def test_simulated_trusted_device_connection_shows_allowed(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    window = MainWindow(auth, user, engine=test_engine)
    qtbot.addWidget(window)

    # Pre-approve a device, then reconnect it via simulation.
    window._usb_monitor.inject_connect("kingston_datatraveler")
    assert _wait_until(lambda: window._pages["devices"].table.rowCount() == 1)

    devices = device_repo.list_devices(engine=test_engine)
    device_repo.approve_device(devices[0].id, user.id, engine=test_engine)

    window._usb_monitor.inject_connect("kingston_datatraveler")
    _pump()

    events = device_repo.get_device_events(devices[0].id, engine=test_engine)
    assert events[0].result == "ALLOWED"


def test_simulated_unknown_device_connection_shows_blocking_failed(qtbot, test_engine, admin_user):
    """On this non-Windows/non-admin sandbox, an unknown device's
    default BLOCK decision must surface as BLOCKING_FAILED, never a
    false BLOCKED."""
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    window = MainWindow(auth, user, engine=test_engine)
    qtbot.addWidget(window)

    window._usb_monitor.inject_connect("unknown_no_serial")
    assert _wait_until(lambda: window._pages["devices"].table.rowCount() == 1)

    devices = device_repo.list_devices(engine=test_engine)
    events = device_repo.get_device_events(devices[0].id, engine=test_engine)
    assert events[0].result == "BLOCKING_FAILED"
