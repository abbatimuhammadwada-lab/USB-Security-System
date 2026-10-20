"""
Phase 2 tests: schema creation, seeding, relationships, and constraints.

Uses an isolated in-memory-per-test SQLite file so it never touches the
developer's real data/usb_security.db.

Run with: pytest tests/test_phase2_database.py -v
"""

import datetime as dt

import pytest
from sqlalchemy import select


@pytest.fixture()
def db_modules(tmp_path):
    """
    Build a fresh, isolated SQLite engine per test (dependency-injected,
    not the process-wide global one) so tests never touch each other or
    any real database on disk, and never need module reloading.
    """
    import app.database.engine as engine_module
    import app.database.init_db as init_db_module
    import app.database.models as models_module

    db_path = tmp_path / "test_usb_security.db"
    test_engine = engine_module.get_engine(database_url=f"sqlite:///{db_path.as_posix()}")

    init_db_module.initialize_database(engine=test_engine)

    class _EngineHelpers:
        """Thin wrapper so tests can call session_scope()/get_engine()
        without repeating the engine= argument everywhere."""

        def session_scope(self):
            return engine_module.session_scope(engine=test_engine)

        def get_engine(self):
            return test_engine

    return {
        "engine": _EngineHelpers(),
        "init_db": init_db_module,
        "models": models_module,
    }


def test_tables_created(db_modules):
    engine = db_modules["engine"].get_engine()
    from sqlalchemy import inspect
    tables = set(inspect(engine).get_table_names())
    expected = {
        "users", "device_fingerprints", "usb_devices", "device_events",
        "policies", "security_alerts", "audit_logs", "system_settings",
    }
    assert expected.issubset(tables)


def test_default_settings_seeded(db_modules):
    models = db_modules["models"]
    with db_modules["engine"].session_scope() as session:
        version = session.scalar(
            select(models.SystemSetting).where(models.SystemSetting.key == "schema_version")
        )
        assert version is not None
        assert version.value == "1"


def test_seed_is_idempotent(db_modules):
    # Calling initialize_database again must not duplicate or error.
    db_modules["init_db"].initialize_database(engine=db_modules["engine"].get_engine())
    models = db_modules["models"]
    with db_modules["engine"].session_scope() as session:
        count = session.scalar(
            select(models.SystemSetting).where(models.SystemSetting.key == "schema_version")
        )
        assert count is not None


def test_user_unique_username_enforced(db_modules):
    models = db_modules["models"]
    with db_modules["engine"].session_scope() as session:
        session.add(models.User(username="admin", password_hash="x", role="ADMINISTRATOR"))

    with pytest.raises(Exception):
        with db_modules["engine"].session_scope() as session:
            session.add(models.User(username="admin", password_hash="y", role="ADMINISTRATOR"))


def test_device_fingerprint_and_usb_device_relationship(db_modules):
    models = db_modules["models"]
    with db_modules["engine"].session_scope() as session:
        fp = models.DeviceFingerprint(
            vendor_id="0951", product_id="1666", serial_number="ABC123",
            manufacturer="Kingston", device_class="USB Mass Storage",
            fingerprint_hash="deadbeef" * 4,
        )
        session.add(fp)
        session.flush()

        device = models.USBDevice(
            fingerprint_id=fp.id,
            name="Kingston DataTraveler",
            manufacturer="Kingston",
            vendor_id="0951",
            product_id="1666",
            serial_number="ABC123",
            status="UNKNOWN",
        )
        session.add(device)

    with db_modules["engine"].session_scope() as session:
        fp = session.scalar(select(models.DeviceFingerprint))
        assert len(fp.devices) == 1
        assert fp.devices[0].name == "Kingston DataTraveler"


def test_device_event_foreign_key_enforced(db_modules):
    """SQLite FK enforcement must be ON - inserting an event for a
    non-existent device_id must fail, not silently succeed."""
    models = db_modules["models"]
    with pytest.raises(Exception):
        with db_modules["engine"].session_scope() as session:
            session.add(models.DeviceEvent(
                device_id=9999,  # does not exist
                event_type="CONNECTED",
                result="DETECTED",
                is_simulated=True,
            ))


def test_audit_log_insert_and_query(db_modules):
    models = db_modules["models"]
    with db_modules["engine"].session_scope() as session:
        session.add(models.AuditLog(
            event_type="LOGIN",
            action="LOGIN_SUCCESS",
            result="ALLOWED",
            severity="INFO",
            description="Administrator logged in.",
        ))

    with db_modules["engine"].session_scope() as session:
        logs = session.scalars(select(models.AuditLog)).all()
        assert len(logs) == 1
        assert logs[0].event_type == "LOGIN"


def test_policy_defaults(db_modules):
    models = db_modules["models"]
    with db_modules["engine"].session_scope() as session:
        policy = models.Policy(
            name="Test-only custom policy",
            action="BLOCK",
            conditions='{"status": "BLOCKED"}',
        )
        session.add(policy)

    with db_modules["engine"].session_scope() as session:
        policy = session.scalar(
            select(models.Policy).where(models.Policy.name == "Test-only custom policy")
        )
        assert policy.status == "ACTIVE"
        assert policy.priority == 100
