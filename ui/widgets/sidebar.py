"""
Sidebar navigation (Section 17).

Presents the sections listed in Section 17's suggested layout: Dashboard,
Devices, Policies, Alerts, Audit Logs, Reports, Settings. Items requiring
permissions the current user lacks (e.g. a Security Analyst viewing
Settings/user management) are still shown for orientation but Section 6
role restrictions are enforced by the pages themselves and by
require_permission() - the sidebar does not silently hide navigation,
since Security Analysts DO have read access to most sections.
"""

from __future__ import annotations

from typing import Callable, NamedTuple, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QButtonGroup


class NavItem(NamedTuple):
    key: str
    label: str


NAV_ITEMS = [
    NavItem("dashboard", "Dashboard"),
    NavItem("devices", "Devices"),
    NavItem("policies", "Policies"),
    NavItem("alerts", "Alerts"),
    NavItem("audit_logs", "Audit Logs"),
    NavItem("reports", "Reports"),
    NavItem("settings", "Settings"),
]


class Sidebar(QWidget):
    navigate = Signal(str)  # emits the NavItem.key of the selected page

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(210)

        self._buttons: dict[str, QPushButton] = {}
        self._button_group = QButtonGroup(self)
        self._button_group.setExclusive(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        title = QLabel("USB SECURITY")
        title.setObjectName("SidebarTitle")
        layout.addWidget(title)

        subtitle = QLabel("Intrusion Detection & Audit")
        subtitle.setObjectName("SidebarSubtitle")
        layout.addWidget(subtitle)

        for item in NAV_ITEMS:
            button = QPushButton(item.label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(lambda _checked, key=item.key: self.navigate.emit(key))
            layout.addWidget(button)
            self._buttons[item.key] = button
            self._button_group.addButton(button)

        layout.addStretch(1)

        self._buttons["dashboard"].setChecked(True)

    def set_active(self, key: str) -> None:
        button = self._buttons.get(key)
        if button is not None:
            button.setChecked(True)
