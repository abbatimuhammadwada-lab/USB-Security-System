"""
Device Registry page (Section 11) - replaces the Phase 4 placeholder.

Lists all detected USB devices with filtering by status, and exposes
Approve / Block / Revoke actions gated by the signed-in user's
permissions (Section 6: Security Analysts get read-only access here).
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QMessageBox, QButtonGroup,
)
from PySide6.QtGui import QColor, QBrush

from app.config.settings import settings
from app.core.enums import DeviceStatus
from app.core.exceptions import AuthorizationError
from app.devices import repository as device_repo
from app.devices.dto import DeviceRecord
from app.security.auth import AuthenticatedUser
from app.security.permissions import Permission, require_permission, has_permission
from app.usb.simulation_monitor import DEVICE_PROFILES
from ui.theme import status_color
from ui.windows.device_detail_dialog import DeviceDetailDialog

_FILTERS = [
    ("All", None),
    ("Trusted", DeviceStatus.TRUSTED.value),
    ("Blocked", DeviceStatus.BLOCKED.value),
    ("Unknown", DeviceStatus.UNKNOWN.value),
    ("Temporary", DeviceStatus.TEMPORARY.value),
]

_COLUMNS = ["Name", "Type", "Manufacturer", "Vendor ID", "Product ID", "Serial", "Status", "First Seen", "Last Seen", "Connections"]


class DevicesPage(QWidget):
    def __init__(
        self,
        user: AuthenticatedUser,
        simulation_monitor=None,  # app.usb.simulation_monitor.SimulationUSBMonitor, optional
        engine=None,  # sqlalchemy.engine.Engine, optional - defaults to the app's global engine
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._user = user
        self._simulation_monitor = simulation_monitor
        self._engine = engine
        self._current_filter: Optional[str] = None
        self._devices: list[DeviceRecord] = []

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        header_row = QHBoxLayout()
        header = QLabel("Device Registry")
        header.setObjectName("SectionTitle")
        header_row.addWidget(header)
        header_row.addStretch(1)

        refresh_button = QPushButton("Refresh")
        refresh_button.setObjectName("SecondaryButton")
        refresh_button.clicked.connect(self.refresh)
        header_row.addWidget(refresh_button)
        layout.addLayout(header_row)

        filter_row = QHBoxLayout()
        self._filter_group = QButtonGroup(self)
        self._filter_group.setExclusive(True)
        for label, status_value in _FILTERS:
            button = QPushButton(label)
            button.setObjectName("SecondaryButton")
            button.setCheckable(True)
            button.setChecked(status_value is None)
            button.clicked.connect(lambda _checked, sv=status_value: self._set_filter(sv))
            self._filter_group.addButton(button)
            filter_row.addWidget(button)
        filter_row.addStretch(1)
        layout.addLayout(filter_row)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(70)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.itemSelectionChanged.connect(self._update_action_buttons)
        self.table.doubleClicked.connect(self._show_details)
        layout.addWidget(self.table, stretch=1)

        action_row = QHBoxLayout()
        self.approve_button = QPushButton("Approve (Trust)")
        self.approve_button.setObjectName("PrimaryButton")
        self.approve_button.clicked.connect(self._approve_selected)

        self.block_button = QPushButton("Block")
        self.block_button.setObjectName("SecondaryButton")
        self.block_button.clicked.connect(self._block_selected)

        self.revoke_button = QPushButton("Revoke")
        self.revoke_button.setObjectName("SecondaryButton")
        self.revoke_button.clicked.connect(self._revoke_selected)

        self.details_button = QPushButton("View Details / History")
        self.details_button.setObjectName("SecondaryButton")
        self.details_button.clicked.connect(self._show_details)

        for btn in (self.approve_button, self.block_button, self.revoke_button, self.details_button):
            btn.setEnabled(False)
            action_row.addWidget(btn)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        if not has_permission(self._user.role, Permission.BLOCK_DEVICE):
            note = QLabel("Your role has read-only access to the device registry.")
            note.setObjectName("PlaceholderNotice")
            layout.addWidget(note)

        if self._simulation_monitor is not None:
            layout.addWidget(self._build_simulation_panel())

    def _build_simulation_panel(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("Card")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(16, 14, 16, 14)

        label = QLabel("SIMULATION MODE - Inject Test Device Events")
        label.setObjectName("CardLabel")
        panel_layout.addWidget(label)

        button_row = QHBoxLayout()
        for profile_key in DEVICE_PROFILES:
            display_name = DEVICE_PROFILES[profile_key].get("name") or profile_key
            connect_btn = QPushButton(f"Connect: {display_name}")
            connect_btn.setObjectName("SecondaryButton")
            connect_btn.clicked.connect(lambda _checked, p=profile_key: self._inject_connect(p))
            button_row.addWidget(connect_btn)
        panel_layout.addLayout(button_row)

        remove_row = QHBoxLayout()
        for profile_key in DEVICE_PROFILES:
            display_name = DEVICE_PROFILES[profile_key].get("name") or profile_key
            remove_btn = QPushButton(f"Remove: {display_name}")
            remove_btn.setObjectName("SecondaryButton")
            remove_btn.clicked.connect(lambda _checked, p=profile_key: self._inject_remove(p))
            remove_row.addWidget(remove_btn)
        panel_layout.addLayout(remove_row)

        return panel

    def _inject_connect(self, profile: str) -> None:
        if self._simulation_monitor is not None:
            self._simulation_monitor.inject_connect(profile)

    def _inject_remove(self, profile: str) -> None:
        if self._simulation_monitor is not None:
            self._simulation_monitor.inject_remove(profile)

    # --- data -------------------------------------------------
    def refresh(self) -> None:
        self._devices = device_repo.list_devices(status_filter=self._current_filter, engine=self._engine)
        self.table.setRowCount(len(self._devices))
        for row, device in enumerate(self._devices):
            values = [
                device.display_name(), device.device_type or "-", device.manufacturer or "-",
                device.vendor_id or "-", device.product_id or "-", device.serial_number or "-",
                device.status, str(device.first_seen), str(device.last_seen), str(device.connection_count),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 6:  # Status column
                    item.setForeground(QBrush(QColor(status_color(device.status))))
                self.table.setItem(row, col, item)
        self._update_action_buttons()

    def _set_filter(self, status_value: Optional[str]) -> None:
        self._current_filter = status_value
        self.refresh()

    def _selected_device(self) -> Optional[DeviceRecord]:
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not rows:
            return None
        row = rows[0].row()
        if row < 0 or row >= len(self._devices):
            return None
        return self._devices[row]

    def _update_action_buttons(self) -> None:
        device = self._selected_device()
        can_manage = has_permission(self._user.role, Permission.BLOCK_DEVICE)
        has_selection = device is not None

        self.details_button.setEnabled(has_selection)
        self.approve_button.setEnabled(has_selection and can_manage and device and device.status != DeviceStatus.TRUSTED.value)
        self.block_button.setEnabled(has_selection and can_manage and device and device.status != DeviceStatus.BLOCKED.value)
        self.revoke_button.setEnabled(has_selection and can_manage and device and device.status != DeviceStatus.UNKNOWN.value)

    # --- actions -------------------------------------------------
    def _approve_selected(self) -> None:
        self._run_action(Permission.REGISTER_TRUSTED_DEVICE, device_repo.approve_device, "approved as trusted")

    def _block_selected(self) -> None:
        self._run_action(Permission.BLOCK_DEVICE, device_repo.block_device, "blocked")

    def _revoke_selected(self) -> None:
        self._run_action(Permission.REVOKE_DEVICE, device_repo.revoke_device, "revoked")

    def _run_action(self, permission: Permission, action_fn, verb: str) -> None:
        device = self._selected_device()
        if device is None:
            return
        try:
            require_permission(self._user.role, permission)
            action_fn(device.id, self._user.id, engine=self._engine)
        except AuthorizationError as exc:
            QMessageBox.warning(self, "Permission denied", str(exc))
            return
        except ValueError as exc:
            QMessageBox.warning(self, "Action failed", str(exc))
            return
        self.refresh()

    def _show_details(self) -> None:
        device = self._selected_device()
        if device is None:
            return
        events = device_repo.get_device_events(device.id, engine=self._engine)
        dialog = DeviceDetailDialog(device, events, parent=self)
        dialog.exec()
