# Security

## Authentication (Section 7)

- Passwords hashed with Argon2id (`argon2-cffi`), never stored or
  logged in plaintext anywhere.
- Failed logins increment a per-account counter; after
  `MAX_FAILED_LOGINS` (default 5) the account locks for
  `LOCKOUT_MINUTES` (default 15) - enforced even against the correct
  password while locked.
- Login error messages are deliberately generic ("Invalid username or
  password") for unknown-username and wrong-password cases, to avoid
  username enumeration; disabled/locked-account messages are more
  specific since these are administrator-managed accounts, not public
  self-service ones.
- No hardcoded default administrator anywhere in source. The first
  administrator is created via `scripts/create_admin.py`, interactively
  (password entered via `getpass`, never echoed) or via
  `DEFAULT_ADMIN_USERNAME`/`DEFAULT_ADMIN_PASSWORD` environment
  variables for scripted setup - and only if no administrator account
  already exists.
- Sessions expire after `SESSION_TIMEOUT_MINUTES` (default 30) of
  inactivity.

## Role-based access control (Section 6)

Enforced centrally in `app/security/permissions.py`, checked by every
repository-calling UI action (`require_permission()`), not just hidden
in the UI:

| Permission | Administrator | Security Analyst |
|---|---|---|
| View dashboard/devices/alerts/audit logs | Yes | Yes |
| Generate reports | Yes | Yes |
| Register/block/revoke devices | Yes | No |
| Create/modify/delete policies | Yes | No |
| Resolve alerts | Yes | No |
| Manage users / configure settings | Yes | No |

## Enforcement honesty (Section 4)

The system distinguishes DETECTED / AUTHORIZED / UNAUTHORIZED / ALLOWED
/ BLOCKED / BLOCKING_FAILED / REMOVED / UNKNOWN throughout the database,
audit log, and UI, and never displays a status implying more happened
than actually did:

- A device's registry **status** (TRUSTED/BLOCKED/UNKNOWN/TEMPORARY) is
  an administrative classification, set only by explicit Approve/Block/
  Revoke actions - never automatically by a connection event.
- A connection **event's result** reflects what actually happened at
  that moment. A BLOCK policy decision triggers a real attempt
  (`app/enforcement/windows_enforcement.py`, `pnputil /disable-device`)
  which requires Windows and administrator privileges; if either is
  missing, or the command itself fails, the result is `BLOCKING_FAILED`
  - never `BLOCKED`.

## Known, honestly-documented limitations

Two modules are implemented against Microsoft's documented mechanisms
but have **not been executed on real Windows hardware** in this
development sandbox (which is Linux):

1. **`app/usb/windows_monitor.py`** - real-time USB detection via WMI's
   `Win32_DeviceChangeEvent`.
2. **`app/enforcement/windows_enforcement.py`** - device-instance
   disabling via `pnputil /disable-device`.

Both fail closed/honestly when their preconditions aren't met (wrong
platform, missing privileges, command failure) rather than pretending
to succeed. Validate both on real Windows hardware before a project
defense - see `docs/testing.md`.

Everything else - database, authentication, the policy engine, the
detection engine, alerts, audit logging, reports, and the entire GUI -
has been executed repeatedly during development in this sandbox via
`SimulationUSBMonitor`, not merely written and assumed correct.

## Secure coding practices applied throughout

- All SQL goes through SQLAlchemy's parameterized query construction -
  no string-formatted SQL anywhere.
- `app/database/engine.py`'s `session_scope()` rolls back on any
  exception, and only re-wraps genuine `SQLAlchemyError`s as
  `DatabaseError` - application-level exceptions (like "device not
  found") propagate with their original type so callers can handle
  them specifically, and so a failed-login's audit record still commits
  even though `AuthenticationError` is raised afterward (see the Phase
  3 development notes for the real bug this fixed).
- No secrets in source; configuration loaded from `.env`
  (`.env.example` is the template, `.env` is gitignored).
- User-facing error dialogs never show raw stack traces - exceptions
  are caught and translated to plain-language messages.
