"""
Main application window (Section 17).

Layout: sidebar navigation on the left, top bar with app title and user
menu (username/role + logout) on top, content area (QStackedWidget)
switching between the pages built in ui/windows/pages.py.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QStackedWidget, QPushButton, QMenu, QSizePolicy,
)
from PySide6.QtGui import QAction

from app.config.constants import APP_TITLE
from app.config.settings import settings
from app.devices import repository as device_repo
from app.policy.pipeline import process_connection_event
from app.security.auth import AuthService, AuthenticatedUser
from app.usb.device_info import USBDeviceInfo
from app.usb.factory import create_usb_monitor
from ui.usb_bridge import USBEventBridge
from ui.widgets.sidebar import Sidebar, NAV_ITEMS
from ui.windows.pages import build_pages


class MainWindow(QMainWindow):
    logout_requested = Signal()

    def __init__(
        self,
        auth_service: AuthService,
        user: AuthenticatedUser,
        engine=None,  # sqlalchemy.engine.Engine, optional - defaults to the app's global engine
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._auth_service = auth_service
        self._user = user
        self._engine = engine

        self.setWindowTitle(f"{APP_TITLE} - {user.username} ({user.role})")
        self.resize(1180, 760)
        self.setMinimumSize(980, 640)

        self._usb_bridge = USBEventBridge()
        self._usb_bridge.device_event.connect(self._handle_usb_event)
        self._usb_monitor = create_usb_monitor(on_event=self._usb_bridge.on_monitor_event)

        self._build_ui()

        self._usb_monitor.start()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        outer_layout = QHBoxLayout(central)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self.sidebar = Sidebar()
        self.sidebar.navigate.connect(self._navigate_to)
        outer_layout.addWidget(self.sidebar)

        right_column = QVBoxLayout()
        right_column.setContentsMargins(0, 0, 0, 0)
        right_column.setSpacing(0)

        right_column.addWidget(self._build_top_bar())

        self.stacked_pages = QStackedWidget()
        simulation_monitor = self._usb_monitor if hasattr(self._usb_monitor, "inject_connect") else None
        self._pages = build_pages(self._user, simulation_monitor=simulation_monitor, engine=self._engine)
        self._page_index: dict[str, int] = {}
        for key, widget in self._pages.items():
            self._page_index[key] = self.stacked_pages.addWidget(widget)
        right_column.addWidget(self.stacked_pages)

        right_container = QWidget()
        right_container.setLayout(right_column)
        outer_layout.addWidget(right_container, stretch=1)

        self._navigate_to("dashboard")
        self._refresh_dashboard_counts()

    def _refresh_dashboard_counts(self) -> None:
        dashboard_page = self._pages.get("dashboard")
        if dashboard_page is not None and hasattr(dashboard_page, "update_counts"):
            from app.alerts.repository import get_alert_counts
            counts = device_repo.get_device_counts(engine=self._engine)
            alert_counts = get_alert_counts(engine=self._engine)
            dashboard_page.update_counts({
                "total_devices": counts.total,
                "authorized": counts.trusted,
                "blocked": counts.blocked,
                "unknown": counts.unknown,
                "alerts": alert_counts["unresolved"],
                "unauthorized_attempts": alert_counts["total"],
            })

    def _build_top_bar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(56)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 20, 0)

        title = QLabel(APP_TITLE)
        title.setObjectName("TopBarTitle")
        title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout.addWidget(title)

        self.simulation_badge = QLabel()
        self.simulation_badge.setObjectName("UserBadge")
        layout.addWidget(self.simulation_badge)
        layout.addSpacing(10)

        user_button = QPushButton(f"{self._user.username} ({self._user.role}) ▾")
        user_button.setObjectName("UserBadge")
        user_button.setCursor(Qt.PointingHandCursor)

        menu = QMenu(user_button)
        logout_action = QAction("Log out", user_button)
        logout_action.triggered.connect(self._handle_logout)
        menu.addAction(logout_action)
        user_button.setMenu(menu)

        layout.addWidget(user_button)
        return bar

    def set_simulation_mode_indicator(self, simulation_mode: bool) -> None:
        if simulation_mode:
            self.simulation_badge.setText("SIMULATION MODE")
            self.simulation_badge.setStyleSheet("color: #FFC24B; border-color: #FFC24B;")
        else:
            self.simulation_badge.setText("LIVE")
            self.simulation_badge.setStyleSheet("color: #3FE07A; border-color: #3FE07A;")
        self.simulation_badge.setVisible(True)

    def _navigate_to(self, key: str) -> None:
        if key in self._page_index:
            self.stacked_pages.setCurrentIndex(self._page_index[key])
            self.sidebar.set_active(key)
            page = self._pages.get(key)
            if page is not None and hasattr(page, "refresh"):
                page.refresh()

    def _handle_usb_event(self, info: USBDeviceInfo) -> None:
        """
        Runs on the GUI thread (Qt queues the cross-thread signal
        delivery automatically). Runs the full detect -> record ->
        evaluate -> enforce -> audit -> detect-intrusions -> alert
        pipeline (Phases 6-9), then refreshes every page with live data
        so whichever screen the operator is looking at reflects it
        immediately, not just on next navigation.
        """
        process_connection_event(info, username=self._user.username, engine=self._engine)

        for page in self._pages.values():
            if hasattr(page, "refresh"):
                page.refresh()

        self._refresh_dashboard_counts()

    def _handle_logout(self) -> None:
        self._auth_service.logout()
        self.logout_requested.emit()
        self.close()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._usb_monitor.stop()
        super().closeEvent(event)
