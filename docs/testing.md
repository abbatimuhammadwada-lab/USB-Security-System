# Testing

## Automated tests

163 automated tests across 11 files, one roughly per development phase. All
run headlessly (Qt's `offscreen` platform plugin, set automatically by
`tests/conftest.py`) and against isolated, temporary SQLite databases -
never the real `data/usb_security.db`.

```bash
pip install pytest pytest-qt
pytest tests/ -v
```

| File | Covers |
|---|---|
| `test_phase1_bootstrap.py` | Config load, directory bootstrap, enum/exception contracts |
| `test_phase2_database.py` | Schema creation, seeding, relationships, foreign-key enforcement |
| `test_phase3_auth.py` | Password hashing, login/lockout, sessions, RBAC, admin bootstrap |
| `test_phase4_gui.py` | Login dialog, main window, navigation, role-gated pages |
| `test_phase5_usb_detection.py` | Fingerprinting, classification, simulation monitor, backend selection |
| `test_phase6_device_registry.py`, `test_phase6_gui.py` | Device registry CRUD, approve/block/revoke, live GUI pipeline |
| `test_phase7_policy_engine.py`, `test_phase7_gui.py` | Condition matching, policy CRUD, evaluation order, enforcement, full pipeline |
| `test_phase8_intrusion_detection.py` | Every detection rule, alert persistence |
| `test_phase10_11_audit_reports.py` | Audit log search, PDF/CSV report generation (verifies real file signatures) |

No unit test requires a physical USB device - `SimulationUSBMonitor`
(Section 24) covers all of them, including the four built-in demo
device profiles in `app/usb/simulation_monitor.py`.

## Manual testing procedure (Section 23)

Run `python main.py`, sign in, and use the **Devices** page's built-in
simulation panel (visible whenever `SIMULATION_MODE=true`, the default)
for every scenario below - no physical hardware needed. On real Windows
hardware with `SIMULATION_MODE=false`, substitute an actual USB device
for each "Connect: ..." step.

### 1. Connect an authorized (trusted) USB
1. Devices page -> click "Connect: Kingston DataTraveler". Confirm it
   appears with status `UNKNOWN`.
2. Select it -> "Approve (Trust)". Confirm status becomes `TRUSTED`.
3. Click "Remove: Kingston DataTraveler", then "Connect: Kingston
   DataTraveler" again.
4. Open "View Details / History" - the newest event's Result column
   should read `ALLOWED`.
5. Dashboard -> "Authorized Devices" count should be 1.

### 2. Connect an unauthorized (never-approved) USB
1. Click "Connect: Generic USB Storage Device" (a fresh, never-seen
   profile).
2. Status shows `UNKNOWN`; event history shows `BLOCKING_FAILED` (this
   sandbox/most dev machines lack the admin privileges real enforcement
   needs - see `docs/security.md`) or `BLOCKED` if run elevated on
   Windows.
3. Alerts page -> confirm `UNKNOWN_USB` and `POLICY_VIOLATION` alerts
   were generated for this device.

### 3. Connect a blacklisted USB
1. Approve then Block a device (or Block it directly from `UNKNOWN`).
2. Reconnect it. Event history shows the enforcement attempt result;
   Alerts page shows a `BLACKLISTED_USB` (HIGH severity) alert.

### 4. Remove USB
1. With any connected simulated device, click its "Remove: ..." button.
2. Devices page -> View Details/History shows a `REMOVED` event with
   the correct timestamp.

### 5. Repeated unauthorized attempts
1. Click "Connect: Generic USB Storage Device" then "Remove: ..." at
   least 5 times within 10 minutes (the default threshold/window -
   configurable via `UNAUTHORIZED_ATTEMPT_THRESHOLD` /
   `UNAUTHORIZED_ATTEMPT_WINDOW_MINUTES` in `.env`).
3. Alerts page -> confirm a `REPEATED_UNAUTHORIZED_ATTEMPTS` (HIGH)
   alert appears.

### 6. Generating reports
1. Reports page -> click "Export PDF" or "Export CSV" for each of the
   three report types.
2. Confirm the status line shows a saved path under `data/reports/`,
   and that opening the file shows real data matching what's on the
   Devices/Alerts/Audit Logs pages.

### 7. Role-based access
1. Create a Security Analyst account (Administrator role required -
   currently via direct DB row until the Settings/user-management
   screen lands; see `docs/user-guide.md`).
2. Sign in as that analyst. Confirm: Devices/Policies pages show no
   Approve/Block/Revoke/Create/Edit/Delete buttons; Settings page shows
   "Access Denied".

## What is NOT verified in this development environment

This sandbox is Linux. `WindowsUSBMonitor` (real WMI-based detection)
and the `pnputil`-based enforcement command have not been executed
against real Windows hardware - see the limitations noted in
`README.md` and `docs/security.md`. Everything else (database, auth,
GUI, policy engine, detection rules, alerts, audit log, reports) has
been run for real, repeatedly, during development - not just written
and assumed to work.
