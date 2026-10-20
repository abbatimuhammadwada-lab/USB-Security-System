"""
Security Alerts page (Section 14) - replaces the Phase 4 placeholder.

All roles can view and filter alerts (Section 6: Security Analysts have
VIEW_ALERTS); resolving an alert requires RESOLVE_ALERT (granted to
Administrators; extend to Security Analysts here if the org's policy
wants that - kept Administrator-only for now, consistent with other
state-changing actions).
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QComboBox, QMessageBox,
)
from PySide6.QtGui import QColor, QBrush

from app.alerts import repository as alert_repo
from app.core.enums import AlertSeverity
from app.core.exceptions import AuthorizationError
from app.security.auth import AuthenticatedUser
from app.security.permissions import Permission, require_permission, has_permission
from ui.theme import severity_color

_COLUMNS = ["Severity", "Type", "Device", "Description", "Created (UTC)", "Read", "Resolved"]


class AlertsPage(QWidget):
    def __init__(self, user: AuthenticatedUser, engine=None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._user = user
        self._engine = engine
        self._alerts = []
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        header_row = QHBoxLayout()
        header = QLabel("Security Alerts")
        header.setObjectName("SectionTitle")
        header_row.addWidget(header)
        header_row.addStretch(1)

        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All Severities", None)
        for sev in AlertSeverity:
            self.severity_filter.addItem(sev.value, sev.value)
        self.severity_filter.currentIndexChanged.connect(lambda _i: self.refresh())
        header_row.addWidget(self.severity_filter)

        self.unresolved_only_button = QPushButton("Show unresolved only")
        self.unresolved_only_button.setObjectName("SecondaryButton")
        self.unresolved_only_button.setCheckable(True)
        self.unresolved_only_button.clicked.connect(lambda: self.refresh())
        header_row.addWidget(self.unresolved_only_button)

        refresh_button = QPushButton("Refresh")
        refresh_button.setObjectName("SecondaryButton")
        refresh_button.clicked.connect(self.refresh)
        header_row.addWidget(refresh_button)
        layout.addLayout(header_row)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(QHeaderView.ResizeToContents)
        header_view.setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        layout.addWidget(self.table, stretch=1)

        action_row = QHBoxLayout()
        self.resolve_button = QPushButton("Mark Resolved")
        self.resolve_button.setObjectName("PrimaryButton")
        self.resolve_button.clicked.connect(self._resolve_selected)
        self.resolve_button.setEnabled(False)
        action_row.addWidget(self.resolve_button)
        action_row.addStretch(1)
        layout.addLayout(action_row)

    def refresh(self) -> None:
        severity = self.severity_filter.currentData()
        unresolved_only = self.unresolved_only_button.isChecked()
        self._alerts = alert_repo.list_alerts(
            severity=severity, unresolved_only=unresolved_only, engine=self._engine
        )
        self.table.setRowCount(len(self._alerts))
        for row, alert in enumerate(self._alerts):
            values = [
                alert.severity, alert.alert_type, alert.device_name or "-",
                alert.description, str(alert.created_at),
                "Yes" if alert.is_read else "No", "Yes" if alert.is_resolved else "No",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 0:
                    item.setForeground(QBrush(QColor(severity_color(alert.severity))))
                self.table.setItem(row, col, item)
        self._update_buttons()

    def _selected_alert(self):
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not rows:
            return None
        row = rows[0].row()
        if row < 0 or row >= len(self._alerts):
            return None
        return self._alerts[row]

    def _update_buttons(self) -> None:
        alert = self._selected_alert()
        can_resolve = has_permission(self._user.role, Permission.RESOLVE_ALERT)
        self.resolve_button.setEnabled(alert is not None and can_resolve and not alert.is_resolved)
        if alert is not None and not alert.is_read:
            alert_repo.mark_read(alert.id, engine=self._engine)

    def _resolve_selected(self) -> None:
        alert = self._selected_alert()
        if alert is None:
            return
        try:
            require_permission(self._user.role, Permission.RESOLVE_ALERT)
            alert_repo.mark_resolved(alert.id, self._user.id, engine=self._engine)
        except (AuthorizationError, ValueError) as exc:
            QMessageBox.warning(self, "Could not resolve alert", str(exc))
            return
        self.refresh()
