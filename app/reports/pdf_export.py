"""PDF export for all three report types (Section 19), using ReportLab."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

from app.config.constants import APP_TITLE
from app.core.exceptions import ReportGenerationError
from app.reports.data import UsbActivityRow, SecurityIncidentRow, DeviceInventoryData

_HEADER_BG = colors.HexColor("#0B0F14")
_ACCENT = colors.HexColor("#1B5A6E")


def _build_doc(path: Path, title: str) -> tuple[SimpleDocTemplate, list]:
    doc = SimpleDocTemplate(str(path), pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    elements = [
        Paragraph(APP_TITLE, styles["Heading2"]),
        Paragraph(title, styles["Heading3"]),
        Paragraph(f"Generated: {dt.datetime.utcnow().isoformat()} UTC", styles["Normal"]),
        Spacer(1, 0.25 * inch),
    ]
    return doc, elements


def _styled_table(data: list[list[str]]) -> Table:
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F0F0F0")]),
    ]))
    return table


def export_usb_activity_pdf(rows: list[UsbActivityRow], path: Path) -> Path:
    try:
        doc, elements = _build_doc(path, "USB Activity Report")
        data = [["Timestamp (UTC)", "Device", "User", "Action", "Result"]]
        for row in rows:
            data.append([str(row.timestamp), row.device_name, row.username or "-", row.action or "-", row.result or "-"])
        if len(data) == 1:
            data.append(["No activity recorded in this period.", "", "", "", ""])
        elements.append(_styled_table(data))
        doc.build(elements)
    except Exception as exc:
        raise ReportGenerationError(f"Failed to generate USB activity PDF: {exc}") from exc
    return path


def export_security_incident_pdf(rows: list[SecurityIncidentRow], path: Path) -> Path:
    try:
        doc, elements = _build_doc(path, "Security Incident Report")
        data = [["Timestamp (UTC)", "Type", "Severity", "Device", "Description", "Resolved"]]
        for row in rows:
            data.append([
                str(row.timestamp), row.alert_type, row.severity, row.device_name or "-",
                row.description[:80], "Yes" if row.resolved else "No",
            ])
        if len(data) == 1:
            data.append(["No incidents recorded in this period.", "", "", "", "", ""])
        elements.append(_styled_table(data))
        doc.build(elements)
    except Exception as exc:
        raise ReportGenerationError(f"Failed to generate security incident PDF: {exc}") from exc
    return path


def export_device_inventory_pdf(data: DeviceInventoryData, path: Path) -> Path:
    try:
        doc, elements = _build_doc(path, "Device Inventory Report")
        styles = getSampleStyleSheet()
        for category, devices in (
            ("Trusted Devices", data.trusted), ("Blocked Devices", data.blocked),
            ("Unknown Devices", data.unknown), ("Temporary Devices", data.temporary),
        ):
            elements.append(Paragraph(category, styles["Heading4"]))
            table_data = [["Name", "Manufacturer", "Vendor ID", "Product ID", "Serial", "First Seen"]]
            for device in devices:
                table_data.append([
                    device.display_name(), device.manufacturer or "-", device.vendor_id or "-",
                    device.product_id or "-", device.serial_number or "-", str(device.first_seen),
                ])
            if len(table_data) == 1:
                table_data.append(["(none)", "", "", "", "", ""])
            elements.append(_styled_table(table_data))
            elements.append(Spacer(1, 0.2 * inch))
        doc.build(elements)
    except Exception as exc:
        raise ReportGenerationError(f"Failed to generate device inventory PDF: {exc}") from exc
    return path
