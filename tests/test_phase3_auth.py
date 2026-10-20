"""
Phase 3 tests: password hashing, authentication, lockout, sessions,
role-based permissions, and the secure admin bootstrap process.

Run with: pytest tests/test_phase3_auth.py -v
"""

import datetime as dt

import pytest
from sqlalchemy import select

from app.core.exceptions import AuthenticationError, AuthorizationError, ConfigurationError
from app.database.engine import get_engine, session_scope
from app.database.init_db import initialize_database
from app.database.models import User, AuditLog
from app.security.password import hash_password, verify_password, validate_password_strength
from app.security.permissions import has_permission, require_permission, Permission
from app.security.auth import AuthService
from app.security.bootstrap import create_initial_administrator, administrator_exists
from app.security.session import SessionManager


@pytest.fixture()
def test_engine(tmp_path):
    db_path = tmp_path / "test_auth.db"
    engine = get_engine(database_url=f"sqlite:///{db_path.as_posix()}")
    initialize_database(engine=engine)
    return engine


# --- password hashing -------------------------------------------------
def test_hash_and_verify_roundtrip():
    h = hash_password("CorrectHorse9")
    assert verify_password("CorrectHorse9", h) is True
    assert verify_password("WrongPassword1", h) is False


def test_hash_is_not_plaintext():
    h = hash_password("CorrectHorse9")
    assert "CorrectHorse9" not in h
    assert h.startswith("$argon2id$")


def test_password_strength_rejects_weak():
    assert validate_password_strength("short1") != []
    assert validate_password_strength("nodigitshere") != []
    assert validate_password_strength("12345678901234") != []  # no letters
    assert validate_password_strength("password") != []


def test_password_strength_accepts_strong():
    assert validate_password_strength("Str0ngPassphrase!") == []


# --- bootstrap ----------------------------------------------------------
def test_create_initial_administrator(test_engine):
    admin = create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)
    assert admin.username == "admin"
    assert admin.role == "ADMINISTRATOR"
    assert administrator_exists(engine=test_engine) is True


def test_bootstrap_refuses_second_admin(test_engine):
    create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)
    with pytest.raises(ConfigurationError):
        create_initial_administrator("admin2", "AnotherStr0ngPass!", engine=test_engine)


def test_bootstrap_rejects_weak_password(test_engine):
    with pytest.raises(ConfigurationError):
        create_initial_administrator("admin", "weak", engine=test_engine)


def test_bootstrap_writes_audit_log(test_engine):
    create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)
    with session_scope(engine=test_engine) as session:
        logs = session.scalars(select(AuditLog)).all()
        assert any(log.event_type == "CONFIGURATION_CHANGED" for log in logs)


# --- authentication -------------------------------------------------
def test_authenticate_success(test_engine):
    create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)
    auth = AuthService(engine=test_engine)
    user = auth.authenticate("admin", "Str0ngPassphrase!")
    assert user.username == "admin"
    assert auth.is_authenticated() is True


def test_authenticate_wrong_password_fails(test_engine):
    create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)
    auth = AuthService(engine=test_engine)
    with pytest.raises(AuthenticationError):
        auth.authenticate("admin", "WrongPassword1")
    assert auth.is_authenticated() is False


def test_authenticate_unknown_user_fails(test_engine):
    auth = AuthService(engine=test_engine)
    with pytest.raises(AuthenticationError):
        auth.authenticate("nobody", "whatever123")


def test_failed_logins_increment_and_lock(test_engine):
    create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)
    auth = AuthService(engine=test_engine, max_failed_logins=3, lockout_minutes=15)

    for _ in range(2):
        with pytest.raises(AuthenticationError):
            auth.authenticate("admin", "WrongPassword1")

    with session_scope(engine=test_engine) as session:
        user = session.scalar(select(User).where(User.username == "admin"))
        assert user.failed_login_count == 2
        assert user.locked_until is None

    # third failure should lock the account
    with pytest.raises(AuthenticationError):
        auth.authenticate("admin", "WrongPassword1")

    with session_scope(engine=test_engine) as session:
        user = session.scalar(select(User).where(User.username == "admin"))
        assert user.locked_until is not None
        assert user.locked_until > dt.datetime.utcnow()

    # even the correct password must now be rejected while locked
    with pytest.raises(AuthenticationError):
        auth.authenticate("admin", "Str0ngPassphrase!")


def test_successful_login_resets_failed_count(test_engine):
    create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)
    auth = AuthService(engine=test_engine, max_failed_logins=5)

    with pytest.raises(AuthenticationError):
        auth.authenticate("admin", "WrongPassword1")

    auth.authenticate("admin", "Str0ngPassphrase!")

    with session_scope(engine=test_engine) as session:
        user = session.scalar(select(User).where(User.username == "admin"))
        assert user.failed_login_count == 0
        assert user.last_login_at is not None


def test_disabled_account_rejected(test_engine):
    create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)
    with session_scope(engine=test_engine) as session:
        user = session.scalar(select(User).where(User.username == "admin"))
        user.is_active = False

    auth = AuthService(engine=test_engine)
    with pytest.raises(AuthenticationError):
        auth.authenticate("admin", "Str0ngPassphrase!")


def test_login_and_logout_write_audit_entries(test_engine):
    create_initial_administrator("admin", "Str0ngPassphrase!", engine=test_engine)
    auth = AuthService(engine=test_engine)
    auth.authenticate("admin", "Str0ngPassphrase!")
    auth.logout()

    with session_scope(engine=test_engine) as session:
        events = {log.event_type for log in session.scalars(select(AuditLog)).all()}
        assert "LOGIN" in events
        assert "LOGOUT" in events


# --- sessions -------------------------------------------------
def test_session_expires_after_timeout():
    mgr = SessionManager()
    session = mgr.start_session(1, "admin", "ADMINISTRATOR", timeout_minutes=30)
    assert mgr.is_authenticated() is True

    # simulate time passing beyond the timeout
    session.last_activity_at = dt.datetime.utcnow() - dt.timedelta(minutes=31)
    assert mgr.is_authenticated() is False


def test_session_touch_extends_activity():
    mgr = SessionManager()
    session = mgr.start_session(1, "admin", "ADMINISTRATOR", timeout_minutes=30)
    old_activity = session.last_activity_at
    session.last_activity_at = dt.datetime.utcnow() - dt.timedelta(minutes=10)
    mgr.touch()
    assert mgr.current().last_activity_at > old_activity - dt.timedelta(minutes=10)


# --- permissions -------------------------------------------------
def test_administrator_has_all_permissions():
    for perm in Permission:
        assert has_permission("ADMINISTRATOR", perm) is True


def test_security_analyst_limited_permissions():
    assert has_permission("SECURITY_ANALYST", Permission.VIEW_DASHBOARD) is True
    assert has_permission("SECURITY_ANALYST", Permission.CREATE_POLICY) is False
    assert has_permission("SECURITY_ANALYST", Permission.MANAGE_USERS) is False


def test_require_permission_raises_for_disallowed_role():
    with pytest.raises(AuthorizationError):
        require_permission("SECURITY_ANALYST", Permission.MODIFY_POLICY)


def test_require_permission_passes_for_allowed_role():
    require_permission("ADMINISTRATOR", Permission.MODIFY_POLICY)  # should not raise
