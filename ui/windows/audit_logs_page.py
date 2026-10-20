"""
Audit Logs page (Section 15) - replaces the Phase 4 placeholder.

Read-only for every role (Section 6: both Administrator and Security
Analyst have VIEW_AUDIT_LOGS). No edit/delete controls exist anywhere
in this screen or its backing repository, by design.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QComboBox,
)
from PySide6.QtGui import QColor, QBrush

from app.logging.query import search_audit_logs, distinct_event_types
from app.security.auth import AuthenticatedUser
from ui.theme import DANGER, WARNING, TEXT_SECONDARY

_SEVERITY_COLORS = {"INFO": TEXT_SECONDARY, "WARNING": WARNING, "HIGH": DANGER, "CRITICAL": DANGER}
_COLUMNS = ["Timestamp (UTC)", "Event Type", "User", "Computer", "Result", "Severity", "Description"]


class AuditLogsPage(QWidget):
    def __init__(self, user: AuthenticatedUser, engine=None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._user = user
        self._engine = engine
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        header_row = QHBoxLayout()
        header = QLabel("Audit Logs")
        header.setObjectName("SectionTitle")
        header_row.addWidget(header)
        header_row.addStretch(1)

        self.event_type_filter = QComboBox()
        self.event_type_filter.addItem("All Event Types", None)
        for event_type in distinct_event_types(engine=self._engine):
            self.event_type_filter.addItem(event_type, event_type)
        self.event_type_filter.currentIndexChanged.connect(lambda _i: self.refresh())
        header_row.addWidget(self.event_type_filter)

        refresh_button = QPushButton("Refresh")
        refresh_button.setObjectName("SecondaryButton")
        refresh_button.clicked.connect(self.refresh)
        header_row.addWidget(refresh_button)
        layout.addLayout(header_row)

        note = QLabel(
            "This log is append-only - entries cannot be edited or deleted through the application."
        )
        note.setObjectName("PlaceholderNotice")
        layout.addWidget(note)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(QHeaderView.ResizeToContents)
        header_view.setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.table, stretch=1)

    def refresh(self) -> None:
        event_type = self.event_type_filter.currentData()
        logs = search_audit_logs(event_type=event_type, limit=500, engine=self._engine)
        self.table.setRowCount(len(logs))
        for row, log in enumerate(logs):
            values = [
                str(log.timestamp), log.event_type, log.username or "-", log.computer_name or "-",
                log.result or "-", log.severity, log.description,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 5:
                    item.setForeground(QBrush(QColor(_SEVERITY_COLORS.get(log.severity, TEXT_SECONDARY))))
                self.table.setItem(row, col, item)
