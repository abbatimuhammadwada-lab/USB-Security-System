# Database

SQLite (`data/usb_security.db` by default, configurable via
`DATABASE_URL` in `.env`), SQLAlchemy 2.0 ORM (`app/database/models.py`).
Foreign-key enforcement is explicitly turned on per-connection (SQLite
defaults it off) - verified by an automated test that a
`device_events` row referencing a nonexistent device actually fails.

Initialization is idempotent `create_all` plus a `schema_version` row
in `system_settings` (`app/database/init_db.py`) rather than a
migrations framework - a deliberate choice for a single-deployment
SQLite desktop app (Rule 5: avoid unnecessary dependencies). If the
schema needs a real ALTER-based migration later, Alembic can be
introduced without touching any of the code that already depends on
`initialize_database()`/`session_scope()`.

## Schema

*(Generated directly from `app/database/models.py`, so this stays
accurate as the schema evolves.)*

### users
- id: INTEGER PK NOT NULL
- username: VARCHAR(64) UNIQUE NOT NULL
- password_hash: VARCHAR(255) NOT NULL
- role: VARCHAR(32) NOT NULL
- is_active: BOOLEAN NOT NULL
- failed_login_count: INTEGER NOT NULL
- locked_until: DATETIME
- created_at: DATETIME NOT NULL
- last_login_at: DATETIME

### device_fingerprints
- id: INTEGER PK NOT NULL
- vendor_id, product_id: VARCHAR(16)
- serial_number: VARCHAR(255)
- pnp_device_id: VARCHAR(512)
- manufacturer: VARCHAR(255)
- device_class: VARCHAR(64)
- fingerprint_hash: VARCHAR(128) UNIQUE NOT NULL

### usb_devices
- id: INTEGER PK NOT NULL
- fingerprint_id: INTEGER FK -> device_fingerprints.id NOT NULL
- name, manufacturer: VARCHAR(255)
- vendor_id, product_id: VARCHAR(16)
- serial_number: VARCHAR(255)
- pnp_device_id: VARCHAR(512)
- device_class, device_type: VARCHAR(64)
- status: VARCHAR(16) NOT NULL (TRUSTED / BLOCKED / UNKNOWN / TEMPORARY)
- first_seen, last_seen: DATETIME NOT NULL
- connection_count: INTEGER NOT NULL
- approved_by: INTEGER FK -> users.id
- approved_at, temporary_expires_at: DATETIME

### device_events
- id: INTEGER PK NOT NULL
- device_id: INTEGER FK -> usb_devices.id NOT NULL
- event_type: VARCHAR(16) NOT NULL (CONNECTED / REMOVED)
- result: VARCHAR(16) NOT NULL (DETECTED/AUTHORIZED/UNAUTHORIZED/ALLOWED/BLOCKED/BLOCKING_FAILED/REMOVED/UNKNOWN)
- is_simulated: BOOLEAN NOT NULL
- user_id: INTEGER FK -> users.id
- computer_name: VARCHAR(255)
- drive_letter: VARCHAR(8)
- timestamp: DATETIME NOT NULL (indexed, plus a composite index with device_id)
- raw_metadata: TEXT (JSON)

### policies
- id: INTEGER PK NOT NULL
- name: VARCHAR(128) NOT NULL
- description: TEXT
- priority: INTEGER NOT NULL (lower = evaluated first)
- conditions: TEXT NOT NULL (JSON)
- action: VARCHAR(16) NOT NULL (ALLOW / BLOCK / ALERT / LOG_ONLY)
- status: VARCHAR(16) NOT NULL (ACTIVE / DISABLED)
- created_by: INTEGER FK -> users.id
- created_at, updated_at: DATETIME NOT NULL

### security_alerts
- id: INTEGER PK NOT NULL
- severity: VARCHAR(16) NOT NULL (indexed)
- alert_type: VARCHAR(64) NOT NULL
- device_id: INTEGER FK -> usb_devices.id
- user_id: INTEGER FK -> users.id
- computer_name: VARCHAR(255)
- description: TEXT NOT NULL
- is_read, is_resolved: BOOLEAN NOT NULL
- resolved_by: INTEGER FK -> users.id
- resolved_at, created_at: DATETIME (created_at indexed)

### audit_logs
- id: INTEGER PK NOT NULL
- timestamp: DATETIME NOT NULL (indexed)
- user_id: INTEGER FK -> users.id
- computer_name: VARCHAR(255)
- event_type: VARCHAR(64) NOT NULL
- device_id: INTEGER FK -> usb_devices.id
- action: VARCHAR(64)
- result: VARCHAR(32)
- severity: VARCHAR(16) NOT NULL
- description: TEXT NOT NULL

No code path anywhere in this project issues an UPDATE or DELETE
against `audit_logs` - it is written once per row and only ever
queried afterward.

### system_settings
- id: INTEGER PK NOT NULL
- key: VARCHAR(128) UNIQUE NOT NULL
- value: TEXT
- updated_at: DATETIME NOT NULL
- updated_by: INTEGER FK -> users.id
