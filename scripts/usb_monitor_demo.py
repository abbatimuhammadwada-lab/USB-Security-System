#!/usr/bin/env python3
"""
USB detection pipeline demo (Section 27, scenarios 3-6).

Starts a USB monitor (simulation backend on non-Windows, or when
SIMULATION_MODE=true), injects a short scripted sequence of connect/
remove events, and prints each one through the full detect -> fingerprint
-> classify pipeline - exactly what Phase 6+ will persist to the device
registry, and what Phase 7+ will hand to the policy engine.

Run with:
    python scripts/usb_monitor_demo.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.usb.device_info import USBDeviceInfo
from app.usb.factory import create_usb_monitor
from app.usb.fingerprint import compute_fingerprint
from app.usb.classifier import classify_device


def handle_event(info: USBDeviceInfo) -> None:
    tag = "[SIMULATED]" if info.is_simulated else "[REAL]"
    device_class = classify_device(info)
    try:
        fp = compute_fingerprint(info)
        fp_display = f"{fp.fingerprint_hash[:16]}... ({fp.strength})"
    except Exception as exc:
        fp_display = f"<could not fingerprint: {exc}>"

    print(
        f"{tag} {info.event_type:9s} | {info.display_name():32s} | "
        f"class={device_class.value:20s} | fingerprint={fp_display} | "
        f"drive={info.drive_letter or '-'}"
    )


def main() -> int:
    print("Starting USB monitor demo...")
    monitor = create_usb_monitor(handle_event)
    print(f"Backend: {type(monitor).__name__}")
    monitor.start()

    if not hasattr(monitor, "inject_connect"):
        print("Real Windows monitor started - connect/remove a physical USB device to see events.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        monitor.stop()
        return 0

    # Simulation backend: run a scripted demo sequence.
    print("\n--- Scenario: unknown device connects ---")
    monitor.inject_connect("unknown_no_serial")
    time.sleep(0.3)

    print("\n--- Scenario: known-profile device connects (would be evaluated by the policy engine in Phase 7) ---")
    monitor.inject_connect("kingston_datatraveler")
    time.sleep(0.3)

    print("\n--- Scenario: peripheral with sparse metadata connects ---")
    monitor.inject_connect("logitech_mouse")
    time.sleep(0.3)

    print("\n--- Scenario: device with NO identifying metadata at all connects (fingerprint fallback) ---")
    monitor.inject_connect("no_metadata_device")
    time.sleep(0.3)

    print("\n--- Scenario: the Kingston drive is removed ---")
    monitor.inject_remove("kingston_datatraveler")
    time.sleep(0.3)

    monitor.stop()
    print("\nDemo complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
