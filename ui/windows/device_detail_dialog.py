"""
Device detail / connection history dialog (Section 11: "View details",
"View history").
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLabel, QTableWidget,
    QTableWidgetItem, QPushButton, QWidget, QHeaderView,
)

from app.devices.dto import DeviceRecord, DeviceEventRecord
from ui.theme import status_color


class DeviceDetailDialog(QDialog):
    def __init__(self, device: DeviceRecord, events: list[DeviceEventRecord], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Device Details - {device.display_name()}")
        self.setMinimumSize(640, 480)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel(device.display_name())
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        status_label = QLabel(device.status)
        status_label.setStyleSheet(f"color: {status_color(device.status)}; font-weight: 600;")
        layout.addWidget(status_label)

        form = QFormLayout()
        form.addRow("Manufacturer:", QLabel(device.manufacturer or "-"))
        form.addRow("Vendor ID:", QLabel(device.vendor_id or "-"))
        form.addRow("Product ID:", QLabel(device.product_id or "-"))
        form.addRow("Serial number:", QLabel(device.serial_number or "-"))
        form.addRow("PnP device ID:", QLabel(device.pnp_device_id or "-"))
        form.addRow("Device class:", QLabel(device.device_class or "-"))
        form.addRow("First seen (UTC):", QLabel(str(device.first_seen)))
        form.addRow("Last seen (UTC):", QLabel(str(device.last_seen)))
        form.addRow("Connection attempts:", QLabel(str(device.connection_count)))
        if device.temporary_expires_at:
            form.addRow("Temporary access expires (UTC):", QLabel(str(device.temporary_expires_at)))
        layout.addLayout(form)

        history_label = QLabel("Connection History")
        history_label.setObjectName("SectionTitle")
        layout.addWidget(history_label)

        table = QTableWidget(len(events), 4)
        table.setHorizontalHeaderLabels(["Timestamp (UTC)", "Event", "Result", "Simulated"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        for row, event in enumerate(events):
            table.setItem(row, 0, QTableWidgetItem(str(event.timestamp)))
            table.setItem(row, 1, QTableWidgetItem(event.event_type))
            result_item = QTableWidgetItem(event.result)
            result_item.setForeground(_color_brush(status_color(event.result)))
            table.setItem(row, 2, result_item)
            table.setItem(row, 3, QTableWidgetItem("Yes" if event.is_simulated else "No"))
        layout.addWidget(table)

        close_button = QPushButton("Close")
        close_button.setObjectName("SecondaryButton")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)


def _color_brush(hex_color: str):
    from PySide6.QtGui import QBrush, QColor
    return QBrush(QColor(hex_color))
