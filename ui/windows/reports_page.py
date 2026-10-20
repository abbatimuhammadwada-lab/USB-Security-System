"""
Reports page (Section 19) - replaces the Phase 4 placeholder.

Generates the three required reports as real PDF/CSV files on disk and
opens the folder / reports the path - gated by GENERATE_REPORTS
(both roles have this per Section 6).
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QMessageBox, QFileDialog,
)

from app.config.settings import settings
from app.core.exceptions import ReportGenerationError
from app.reports import data as report_data
from app.reports import pdf_export, csv_export
from app.security.auth import AuthenticatedUser


class ReportsPage(QWidget):
    def __init__(self, user: AuthenticatedUser, engine=None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._user = user
        self._engine = engine
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        header = QLabel("Reports")
        header.setObjectName("SectionTitle")
        layout.addWidget(header)

        note = QLabel(f"Reports are saved to: {settings.reports_dir}")
        note.setObjectName("PlaceholderNotice")
        layout.addWidget(note)

        for title, description, generate_fn in (
            ("USB Activity Report", "Every recorded connect/remove and access decision.", self._generate_activity),
            ("Security Incident Report", "All security alerts raised by the intrusion detection engine.", self._generate_incident),
            ("Device Inventory Report", "Full device registry grouped by trust status.", self._generate_inventory),
        ):
            layout.addWidget(self._build_report_row(title, description, generate_fn))

        self.status_label = QLabel("")
        self.status_label.setObjectName("PlaceholderNotice")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        layout.addStretch(1)

    def _build_report_row(self, title: str, description: str, generate_fn) -> QWidget:
        row = QWidget()
        row.setObjectName("Card")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(16, 14, 16, 14)

        text_col = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setObjectName("CardLabel")
        desc_label = QLabel(description)
        desc_label.setObjectName("PlaceholderNotice")
        text_col.addWidget(title_label)
        text_col.addWidget(desc_label)
        row_layout.addLayout(text_col, stretch=1)

        pdf_button = QPushButton("Export PDF")
        pdf_button.setObjectName("SecondaryButton")
        pdf_button.clicked.connect(lambda: generate_fn("pdf"))
        row_layout.addWidget(pdf_button)

        csv_button = QPushButton("Export CSV")
        csv_button.setObjectName("PrimaryButton")
        csv_button.clicked.connect(lambda: generate_fn("csv"))
        row_layout.addWidget(csv_button)

        return row

    def _timestamped_path(self, base_name: str, extension: str) -> Path:
        stamp = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return settings.reports_dir / f"{base_name}_{stamp}.{extension}"

    def _generate_activity(self, fmt: str) -> None:
        self._run_generation(
            "USB Activity Report", "usb_activity", fmt,
            lambda: report_data.build_usb_activity_report(engine=self._engine),
            pdf_export.export_usb_activity_pdf, csv_export.export_usb_activity_csv,
        )

    def _generate_incident(self, fmt: str) -> None:
        self._run_generation(
            "Security Incident Report", "security_incident", fmt,
            lambda: report_data.build_security_incident_report(engine=self._engine),
            pdf_export.export_security_incident_pdf, csv_export.export_security_incident_csv,
        )

    def _generate_inventory(self, fmt: str) -> None:
        self._run_generation(
            "Device Inventory Report", "device_inventory", fmt,
            lambda: report_data.build_device_inventory_report(engine=self._engine),
            pdf_export.export_device_inventory_pdf, csv_export.export_device_inventory_csv,
        )

    def _run_generation(self, label: str, base_name: str, fmt: str, data_fn, pdf_fn, csv_fn) -> None:
        try:
            data = data_fn()
            path = self._timestamped_path(base_name, fmt)
            if fmt == "pdf":
                pdf_fn(data, path)
            else:
                csv_fn(data, path)
        except ReportGenerationError as exc:
            QMessageBox.warning(self, "Report generation failed", str(exc))
            return

        from app.logging.audit import write_audit_log
        from app.core.enums import AuditEventType
        from app.database.engine import session_scope
        with session_scope(engine=self._engine) as session:
            write_audit_log(
                session, AuditEventType.REPORT_GENERATED,
                f"{label} ({fmt.upper()}) generated by {self._user.username}.",
                user_id=self._user.id, result="ALLOWED",
            )

        self.status_label.setText(f"{label} saved to: {path}")
