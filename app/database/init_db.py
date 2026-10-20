"""
Database initialization and seed process (Section 18: "Use migrations or
a reliable initialization mechanism").

This project deliberately does not pull in Alembic (Rule 5: avoid
unnecessary dependencies) - for a SQLite-backed single-deployment desktop
app, a versioned `create_all` + an explicit `schema_version` row in
`system_settings` is simpler, auditable, and sufficient. If the project
later needs real migrations (e.g. altering an existing column), Alembic
can be introduced without disrupting this module's public functions.
"""

from __future__ import annotations

import datetime as dt
import json
import logging

from sqlalchemy import select
from sqlalchemy.engine import Engine

from app.database.base import Base
from app.database.engine import get_engine, session_scope
from app.database.models import SystemSetting, Policy
# Import all model modules so their tables register on Base.metadata
from app.database import models  # noqa: F401

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1"

_DEFAULT_SETTINGS = {
    "schema_version": SCHEMA_VERSION,
    "simulation_mode": "true",
    "unauthorized_attempt_threshold": "5",
    "unauthorized_attempt_window_minutes": "10",
    "business_hours_start": "08:00",
    "business_hours_end": "18:00",
    "after_hours_enforcement_enabled": "false",
}


def create_all_tables(engine: Engine | None = None) -> None:
    """Create all tables that do not yet exist. Never drops or alters existing tables."""
    target_engine = engine if engine is not None else get_engine()
    Base.metadata.create_all(bind=target_engine)
    logger.info("Database tables ensured (create_all).")


def seed_default_settings(engine: Engine | None = None) -> None:
    """Insert default system_settings rows only if they do not already exist."""
    with session_scope(engine=engine) as session:
        existing_keys = set(
            session.scalars(select(SystemSetting.key)).all()
        )
        inserted = 0
        for key, value in _DEFAULT_SETTINGS.items():
            if key not in existing_keys:
                session.add(SystemSetting(key=key, value=value, updated_at=dt.datetime.utcnow()))
                inserted += 1
        if inserted:
            logger.info(f"Seeded {inserted} default system_settings row(s).")


def get_schema_version(engine: Engine | None = None) -> str | None:
    with session_scope(engine=engine) as session:
        row = session.scalar(
            select(SystemSetting).where(SystemSetting.key == "schema_version")
        )
        return row.value if row else None


def seed_default_policies(engine: Engine | None = None) -> None:
    """
    Seed the three baseline policies described in Section 12/13, if the
    policies table is empty. Administrators can edit, disable, delete,
    or add to these afterward - this only runs when NO policies exist
    yet, so it never overwrites customization.

    Note on "unknown devices": Section 13's example reads "ALERT + BLOCK"
    for unknown devices. This policy engine's `action` column is a single
    value (Section 12 explicitly lists ALLOW/BLOCK/ALERT/LOG_ONLY as the
    action set), so the BLOCK half is expressed here; the ALERT half is
    generated independently by the intrusion-detection engine (Phase 8),
    which flags "previously-unapproved device connected" as one of its
    own trigger conditions regardless of what this policy decides. This
    keeps policy *decisions* and *alerting* as separate, composable
    concerns rather than overloading one column with two meanings.
    """
    from app.core.enums import DeviceStatus, PolicyAction, PolicyStatus

    with session_scope(engine=engine) as session:
        existing = session.scalar(select(Policy.id).limit(1))
        if existing is not None:
            return  # policies already exist - never overwrite admin customization

        defaults = [
            Policy(
                name="Allow trusted devices",
                description="Devices explicitly approved by an administrator, "
                             "including devices with an active temporary authorization.",
                priority=10,
                conditions=json.dumps({"device_status": [DeviceStatus.TRUSTED.value, DeviceStatus.TEMPORARY.value]}),
                action=PolicyAction.ALLOW.value,
                status=PolicyStatus.ACTIVE.value,
            ),
            Policy(
                name="Block blacklisted devices",
                description="Devices explicitly blocked by an administrator.",
                priority=20,
                conditions=json.dumps({"device_status": [DeviceStatus.BLOCKED.value]}),
                action=PolicyAction.BLOCK.value,
                status=PolicyStatus.ACTIVE.value,
            ),
            Policy(
                name="Block unknown devices by default",
                description="Devices that have never been reviewed by an administrator. "
                             "Deny by default until explicitly approved (fail-closed).",
                priority=100,
                conditions=json.dumps({"device_status": [DeviceStatus.UNKNOWN.value]}),
                action=PolicyAction.BLOCK.value,
                status=PolicyStatus.ACTIVE.value,
            ),
        ]
        session.add_all(defaults)
        logger.info("Seeded 3 default policies (allow-trusted, block-blacklisted, block-unknown).")


def initialize_database(engine: Engine | None = None) -> None:
    """
    Full initialization entry point: create tables, then seed defaults.
    Idempotent - safe to call every application startup.

    Pass an explicit `engine` to initialize a non-default database, such
    as an isolated test database, without touching the global one.
    """
    create_all_tables(engine=engine)
    seed_default_settings(engine=engine)
    seed_default_policies(engine=engine)
    version = get_schema_version(engine=engine)
    logger.info(f"Database ready. schema_version={version}")
