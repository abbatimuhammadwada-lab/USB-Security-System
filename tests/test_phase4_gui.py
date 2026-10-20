"""
Phase 4 GUI tests.

Runs headlessly via the Qt "offscreen" platform plugin (set in
conftest.py) - no real display required, suitable for CI. Exercises
real widgets, real signal/slot wiring, and the real AuthService - not
mocked stand-ins - against an isolated test database.

Run with: pytest tests/test_phase4_gui.py -v
"""

import pytest
from PySide6.QtCore import Qt

from app.database.engine import get_engine
from app.database.init_db import initialize_database
from app.security.auth import AuthService
from app.security.bootstrap import create_initial_administrator
from app.security.permissions import Permission, has_permission
from ui.windows.login_window import LoginDialog
from ui.windows.main_window import MainWindow
from ui.widgets.sidebar import Sidebar, NAV_ITEMS
from ui.windows.pages import build_pages, AccessDeniedPage


@pytest.fixture()
def test_engine(tmp_path):
    db_path = tmp_path / "test_gui.db"
    engine = get_engine(database_url=f"sqlite:///{db_path.as_posix()}")
    initialize_database(engine=engine)
    return engine


@pytest.fixture()
def admin_user(test_engine):
    return create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)


@pytest.fixture()
def analyst_user(test_engine):
    from app.security.password import hash_password
    from app.database.engine import session_scope
    from app.database.models import User
    with session_scope(engine=test_engine) as session:
        analyst = User(username="analyst", password_hash=hash_password("Str0ngPassphrase!"), role="SECURITY_ANALYST")
        session.add(analyst)


# --- Sidebar -------------------------------------------------
def test_sidebar_has_all_required_sections(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    keys = {item.key for item in NAV_ITEMS}
    assert keys == {"dashboard", "devices", "policies", "alerts", "audit_logs", "reports", "settings"}


def test_sidebar_navigate_signal(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    with qtbot.waitSignal(sidebar.navigate, timeout=1000) as blocker:
        sidebar._buttons["devices"].click()
    assert blocker.args == ["devices"]


# --- Login dialog -------------------------------------------------
def test_login_dialog_rejects_empty_fields(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    dialog = LoginDialog(auth)
    qtbot.addWidget(dialog)
    dialog.show()
    dialog._attempt_login()
    assert dialog.error_label.text() != ""
    assert dialog.result() != LoginDialog.Accepted


def test_login_dialog_rejects_wrong_password(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    dialog = LoginDialog(auth)
    qtbot.addWidget(dialog)
    dialog.show()
    dialog.username_input.setText("admin")
    dialog.password_input.setText("WrongPassword1")
    dialog._attempt_login()
    assert "Invalid username or password" in dialog.error_label.text()


def test_login_dialog_accepts_correct_credentials(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    dialog = LoginDialog(auth)
    qtbot.addWidget(dialog)
    dialog.username_input.setText("admin")
    dialog.password_input.setText("Str0ngPassphrase!")
    dialog._attempt_login()
    assert dialog.authenticated_user is not None
    assert dialog.authenticated_user.username == "admin"
    assert auth.is_authenticated() is True


# --- Main window -------------------------------------------------
def test_main_window_builds_all_pages_for_admin(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    window = MainWindow(auth, user, engine=test_engine)
    qtbot.addWidget(window)
    assert set(window._page_index.keys()) == {
        "dashboard", "devices", "policies", "alerts", "audit_logs", "reports", "settings"
    }


def test_main_window_navigation_switches_page(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    window = MainWindow(auth, user, engine=test_engine)
    qtbot.addWidget(window)

    window._navigate_to("devices")
    assert window.stacked_pages.currentIndex() == window._page_index["devices"]


def test_main_window_logout_ends_session(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    window = MainWindow(auth, user, engine=test_engine)
    qtbot.addWidget(window)

    assert auth.is_authenticated() is True
    window._handle_logout()
    assert auth.is_authenticated() is False


# --- Role-gated pages -------------------------------------------------
def test_analyst_cannot_access_settings_page(qtbot, test_engine, analyst_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("analyst", "Str0ngPassphrase!")
    pages = build_pages(user, engine=test_engine)
    assert isinstance(pages["settings"], AccessDeniedPage)


def test_analyst_can_access_dashboard(qtbot, test_engine, analyst_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("analyst", "Str0ngPassphrase!")
    pages = build_pages(user, engine=test_engine)
    from ui.windows.pages import DashboardPage
    assert isinstance(pages["dashboard"], DashboardPage)


def test_admin_can_access_settings_page(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    pages = build_pages(user, engine=test_engine)
    assert not isinstance(pages["settings"], AccessDeniedPage)


# --- Dashboard stat cards -------------------------------------------------
def test_dashboard_cards_start_at_zero_not_fake_data(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    from ui.windows.pages import DashboardPage
    page = DashboardPage(user)
    qtbot.addWidget(page)
    assert page.total_devices_card.value_widget.text() == "0"
    assert page.blocked_card.value_widget.text() == "0"


def test_dashboard_update_counts_reflects_real_values(qtbot, test_engine, admin_user):
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    from ui.windows.pages import DashboardPage
    page = DashboardPage(user)
    qtbot.addWidget(page)
    page.update_counts({"total_devices": 5, "blocked": 2})
    assert page.total_devices_card.value_widget.text() == "5"
    assert page.blocked_card.value_widget.text() == "2"
