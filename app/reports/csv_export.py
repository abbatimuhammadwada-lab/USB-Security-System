"""CSV export for all three report types (Section 19)."""

from __future__ import annotations

import csv
from pathlib import Path

from app.reports.data import UsbActivityRow, SecurityIncidentRow, DeviceInventoryData


def export_usb_activity_csv(rows: list[UsbActivityRow], path: Path) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp (UTC)", "Device", "User", "Action", "Result"])
        for row in rows:
            writer.writerow([row.timestamp, row.device_name, row.username or "-", row.action, row.result])
    return path


def export_security_incident_csv(rows: list[SecurityIncidentRow], path: Path) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp (UTC)", "Type", "Severity", "Device", "Description", "Resolved"])
        for row in rows:
            writer.writerow([
                row.timestamp, row.alert_type, row.severity, row.device_name or "-",
                row.description, "Yes" if row.resolved else "No",
            ])
    return path


def export_device_inventory_csv(data: DeviceInventoryData, path: Path) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Name", "Manufacturer", "Vendor ID", "Product ID", "Serial", "First Seen", "Last Seen"])
        for category, devices in (
            ("Trusted", data.trusted), ("Blocked", data.blocked),
            ("Unknown", data.unknown), ("Temporary", data.temporary),
        ):
            for device in devices:
                writer.writerow([
                    category, device.display_name(), device.manufacturer or "-",
                    device.vendor_id or "-", device.product_id or "-", device.serial_number or "-",
                    device.first_seen, device.last_seen,
                ])
    return path
