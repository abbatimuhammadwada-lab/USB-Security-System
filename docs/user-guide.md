# User Guide

## First run

```bash
python scripts/create_admin.py    # one-time: create the first administrator
python main.py                     # sign in, dashboard opens
```

## Dashboard

Six live stat cards (Total/Authorized/Blocked/Unknown devices, Security
Alerts, Unauthorized Attempts) and a Recent Activity feed pulled from
the real audit trail - updates automatically as devices connect.

## Devices

Lists every USB device the system has ever seen, deduplicated by
hardware fingerprint. Filter by status using the tabs. Select a device
to:
- **Approve (Trust)** - future connections are allowed.
- **Block** - future connections are denied (and enforcement is
  attempted on Windows with administrator privileges).
- **Revoke** - return the device to `UNKNOWN`.
- **View Details / History** - full metadata and every connect/remove
  event recorded for this physical device.

When `SIMULATION_MODE=true` (the default), an inline panel lets you
inject connect/remove events for four built-in demo device profiles -
no physical hardware needed to try any of this.

## Policies

Administrators only (Security Analysts see this page read-only). Three
default policies ship out of the box (Allow trusted, Block blacklisted,
Block unknown-by-default) and are evaluated in priority order - lowest
number first, first match wins. Create a new policy to override the
defaults for specific vendors, device classes, or time windows (e.g.
"only allow this vendor's devices 08:00-18:00").

## Alerts

Every pattern the intrusion detection engine recognizes - unknown
device, blacklisted device, policy violation, repeated unauthorized
attempts, rapid connect/disconnect, after-hours connection - appears
here with a severity. Administrators can mark an alert resolved.

## Audit Logs

The complete, append-only history of every security-relevant event:
logins, USB activity, policy/device changes, alerts, report generation.
Filter by event type. Nothing here can be edited or deleted through the
application.

## Reports

Three report types, each exportable as PDF or CSV, saved under
`data/reports/`:
- **USB Activity Report** - every connect/remove and access decision.
- **Security Incident Report** - every alert the detection engine raised.
- **Device Inventory Report** - the full registry, grouped by trust status.

## Managing additional users

The Settings screen's user-management UI is not yet built (tracked for
a future phase). Until then, an administrator can create a Security
Analyst account directly via a short Python snippet:

```python
from app.database.init_db import initialize_database
from app.database.engine import session_scope
from app.database.models import User
from app.security.password import hash_password

initialize_database()
with session_scope() as session:
    session.add(User(
        username="analyst1",
        password_hash=hash_password("A-Strong-Passphrase-1"),
        role="SECURITY_ANALYST",
    ))
```

## Administrator privileges

Most of the application works without elevation. Real device
**enforcement** (actually disabling a blocked USB device on Windows)
requires running the application as Administrator - without that, a
BLOCK decision is still attempted and honestly recorded as
`BLOCKING_FAILED` rather than silently succeeding or being skipped.
