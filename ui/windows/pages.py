"""
Page content for each sidebar section (Section 17).

Phase 4 builds the layout shell only. Pages that depend on data sources
not yet implemented (device registry: Phase 6, policies: Phase 7,
alerts: Phase 9, audit logs: Phase 10, reports: Phase 11) show an
honest "not yet implemented" placeholder rather than fabricated sample
data - Rule 13: "Never pretend unsupported functionality works."

DashboardPage is the one exception worth building out now: its stat
cards are real widgets wired to real query functions, but since no USB
devices/alerts/policies exist yet in a fresh Phase-4 install, they
correctly show zero. Later phases connect real, changing values - the
widgets do not need to change, only the values they're given.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView,
)

from app.security.auth import AuthenticatedUser
from app.security.permissions import has_permission, Permission
from ui.widgets.stat_card import StatCard
from ui.theme import SUCCESS, DANGER, WARNING, ACCENT
from ui.windows.devices_page import DevicesPage
from ui.windows.policies_page import PoliciesPage
from ui.windows.alerts_page import AlertsPage
from ui.windows.audit_logs_page import AuditLogsPage
from ui.windows.reports_page import ReportsPage


class DashboardPage(QWidget):
    def __init__(self, user: AuthenticatedUser, engine=None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._engine = engine
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)

        header = QLabel("Security Overview")
        header.setObjectName("SectionTitle")
        layout.addWidget(header)

        notice = QLabel(
            "Counts update automatically as USB devices are detected. "
            "Connect (or, in simulation mode, inject) a device to see this "
            "change."
        )
        notice.setObjectName("PlaceholderNotice")
        notice.setWordWrap(True)
        layout.addWidget(notice)

        grid = QGridLayout()
        grid.setSpacing(14)

        self.total_devices_card = StatCard("Total USB Devices", "0")
        self.authorized_card = StatCard("Authorized Devices", "0", accent_color=SUCCESS)
        self.blocked_card = StatCard("Blocked Devices", "0", accent_color=DANGER)
        self.unknown_card = StatCard("Unknown Devices", "0", accent_color=WARNING)
        self.alerts_card = StatCard("Security Alerts", "0", accent_color=DANGER)
        self.unauthorized_card = StatCard("Unauthorized Attempts", "0", accent_color=WARNING)

        cards = [
            self.total_devices_card, self.authorized_card, self.blocked_card,
            self.unknown_card, self.alerts_card, self.unauthorized_card,
        ]
        for i, card in enumerate(cards):
            grid.addWidget(card, i // 3, i % 3)

        layout.addLayout(grid)

        recent_section = QLabel("Recent Activity")
        recent_section.setObjectName("SectionTitle")
        layout.addWidget(recent_section)

        self.recent_table = QTableWidget(0, 4)
        self.recent_table.setHorizontalHeaderLabels(["Timestamp (UTC)", "Event", "Result", "Description"])
        recent_header = self.recent_table.horizontalHeader()
        recent_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        recent_header.setStretchLastSection(True)
        self.recent_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.recent_table.setMaximumHeight(220)
        layout.addWidget(self.recent_table)

        layout.addStretch(1)

    def update_counts(self, counts: dict[str, int]) -> None:
        """Called by later phases once real query functions exist."""
        self.total_devices_card.set_value(str(counts.get("total_devices", 0)))
        self.authorized_card.set_value(str(counts.get("authorized", 0)))
        self.blocked_card.set_value(str(counts.get("blocked", 0)))
        self.unknown_card.set_value(str(counts.get("unknown", 0)))
        self.alerts_card.set_value(str(counts.get("alerts", 0)))
        self.unauthorized_card.set_value(str(counts.get("unauthorized_attempts", 0)))

    def refresh(self) -> None:
        """Populate the recent-activity table from the real audit trail."""
        from app.logging.query import search_audit_logs
        logs = search_audit_logs(limit=15, engine=self._engine)
        self.recent_table.setRowCount(len(logs))
        for row, log in enumerate(logs):
            values = [str(log.timestamp), log.event_type, log.result or "-", log.description]
            for col, value in enumerate(values):
                self.recent_table.setItem(row, col, QTableWidgetItem(value))


class PlaceholderPage(QWidget):
    """Generic 'not yet implemented' page for sections whose backing
    module arrives in a later phase. Named per-page so it's obvious in
    the UI which phase to expect it in - not a silent dead end."""

    def __init__(self, title: str, description: str, implemented_in_phase: str,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(10)

        header = QLabel(title)
        header.setObjectName("SectionTitle")
        layout.addWidget(header)

        desc = QLabel(description)
        desc.setObjectName("PlaceholderNotice")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        phase_note = QLabel(f"Scheduled for: {implemented_in_phase}")
        phase_note.setObjectName("PlaceholderNotice")
        layout.addWidget(phase_note)

        layout.addStretch(1)


class AccessDeniedPage(QWidget):
    """Shown if a signed-in user without the required permission somehow
    navigates to a restricted page - defense in depth alongside the
    sidebar and any future menu-level gating."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        header = QLabel("Access Denied")
        header.setObjectName("SectionTitle")
        header.setStyleSheet(f"color: {DANGER};")
        layout.addWidget(header)
        desc = QLabel("Your role does not have permission to view this section.")
        desc.setObjectName("PlaceholderNotice")
        layout.addWidget(desc)
        layout.addStretch(1)


def build_pages(user: AuthenticatedUser, simulation_monitor=None, engine=None) -> dict[str, QWidget]:
    """
    Build every page for the main window, gating restricted pages by the
    signed-in user's role (Section 6).
    """
    pages: dict[str, QWidget] = {
        "dashboard": DashboardPage(user, engine=engine),
        "devices": DevicesPage(user, simulation_monitor=simulation_monitor, engine=engine),
        "policies": PoliciesPage(user, engine=engine),
        "alerts": AlertsPage(user, engine=engine),
        "audit_logs": AuditLogsPage(user, engine=engine),
        "reports": ReportsPage(user, engine=engine),
        "settings": (
            PlaceholderPage(
                "Settings",
                "User management and system configuration will be "
                "available here.",
                "Phase 14 - Final wiring of settings UI",
            )
            if has_permission(user.role, Permission.CONFIGURE_SETTINGS)
            else AccessDeniedPage()
        ),
    }
    return pages
