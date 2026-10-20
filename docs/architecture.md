# Architecture

## Pipeline

```
Detect -> Identify -> Evaluate -> Allow/Block -> Alert -> Log -> Report
```

Concretely, one USB connection event flows through:

1. **`app/usb/`** (Phase 5) - `WindowsUSBMonitor` (real, WMI-based) or
   `SimulationUSBMonitor` (Section 24) produces a `USBDeviceInfo`.
2. **`app/devices/repository.py`** (Phase 6) - fingerprints the device
   (`app/usb/fingerprint.py`), classifies it (`app/usb/classifier.py`),
   gets-or-creates its `usb_devices`/`device_fingerprints` rows, and
   records a `device_events` row with `result=DETECTED`.
3. **`app/policy/engine.py`** (Phase 7) - evaluates active `policies`
   rows in priority order against the device's context; first match
   wins; fails closed (BLOCK) if nothing matches.
4. **`app/enforcement/windows_enforcement.py`** - if the decision is
   BLOCK, attempts a real `pnputil` device-disable; the event's `result`
   becomes `BLOCKED` or `BLOCKING_FAILED` depending on whether it
   actually succeeded - never claimed without having tried.
5. **`app/detection/`** (Phase 8) - runs rule-based intrusion checks
   (unknown/blacklisted device, policy violation, repeated unauthorized
   attempts, rapid connect/disconnect, after-hours) against the same
   event.
6. **`app/alerts/repository.py`** (Phase 9) - persists every triggered
   check as a `security_alerts` row.
7. **`app/logging/audit.py`** - every step above writes an `audit_logs`
   row in the same transaction as the state change it documents.
8. **`app/reports/`** (Phase 11) - assembles and exports PDF/CSV reports
   from the same repositories.

All of this is orchestrated by **`app/policy/pipeline.py`**'s
`process_connection_event()`, the single entry point both the live GUI
(`ui/windows/main_window.py`) and the console demo script
(`scripts/usb_monitor_demo.py`) call.

## Threading model

`WindowsUSBMonitor`/`SimulationUSBMonitor` run on a background thread
(Section 8: event-driven, not polling). `ui/usb_bridge.py`'s
`USBEventBridge` is a `QObject` whose `device_event` Qt signal is
emitted from that background thread; Qt automatically queues the
delivery to the GUI thread, so `MainWindow._handle_usb_event()` (which
touches the database and Qt widgets) always runs safely on the main
thread despite being triggered from elsewhere.

## Module boundaries

| Package | Owns | Does NOT own |
|---|---|---|
| `app/usb/` | Detecting connect/remove events, fingerprinting, classification | Persistence, policy decisions |
| `app/devices/` | The device registry (trust status, connection history) | Whether a connection should be allowed |
| `app/policy/` | Evaluating ALLOW/BLOCK/ALERT/LOG_ONLY decisions | Actually disabling a device |
| `app/enforcement/` | Attempting real Windows-level enforcement | Deciding whether to enforce |
| `app/detection/` | Recognizing intrusion patterns | Storing/displaying alerts |
| `app/alerts/` | Persisting and querying security alerts | Deciding what counts as suspicious |
| `app/logging/` | The append-only audit trail (write + search) | Business logic |
| `app/reports/` | Assembling and exporting report data | Data collection |
| `app/security/` | Authentication, sessions, RBAC, password hashing | - |
| `ui/` | Presentation only - every page delegates to the `app/*` repositories above | Business logic (Rule 8: "Do not put business logic inside GUI widgets") |

## Dependency-injection pattern

Every repository/service function accepts an optional `engine=` (or, for
`AuthService`/`SessionManager`, constructor) parameter defaulting to the
process-wide global. This is what let 163 automated tests run against
isolated, disposable SQLite databases without a single test touching
another test's data or the real `data/usb_security.db` - and it is also
how `MainWindow`/pages avoid ever silently falling back to an
uninitialized global engine (a real bug caught during Phase 6
development; see the Phase 6 completion notes for details).
