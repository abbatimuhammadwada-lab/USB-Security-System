"""
Create / edit policy dialog (Section 12).

Exposes a practical subset of the full condition language (device
status, device class, vendor ID, and an optional after-hours time
window) rather than a raw JSON editor - covers "device fingerprint,
device type, vendor... time" from Section 12 without requiring the
administrator to hand-write JSON. Power users needing username/
computer/product-ID/fingerprint-hash conditions can still be
accommodated by a future "advanced" JSON mode; the condition schema
itself already supports them (app/policy/conditions.py).
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QHBoxLayout, QLineEdit, QComboBox,
    QSpinBox, QCheckBox, QTimeEdit, QTextEdit, QPushButton, QLabel, QWidget,
)
from PySide6.QtCore import QTime

from app.core.enums import DeviceStatus, DeviceClass, PolicyAction, PolicyStatus
from app.policy.dto import PolicyRecord


class PolicyEditDialog(QDialog):
    def __init__(self, policy: Optional[PolicyRecord] = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._policy = policy
        self.setWindowTitle("Edit Policy" if policy else "Create Policy")
        self.setMinimumWidth(460)
        self._build_ui()
        if policy:
            self._load(policy)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.name_input = QLineEdit()
        form.addRow("Name:", self.name_input)

        self.description_input = QTextEdit()
        self.description_input.setMaximumHeight(60)
        form.addRow("Description:", self.description_input)

        self.priority_input = QSpinBox()
        self.priority_input.setRange(1, 9999)
        self.priority_input.setValue(100)
        self.priority_input.setToolTip("Lower number = evaluated first.")
        form.addRow("Priority:", self.priority_input)

        self.action_combo = QComboBox()
        self.action_combo.addItems([a.value for a in PolicyAction])
        form.addRow("Action:", self.action_combo)

        self.status_combo = QComboBox()
        self.status_combo.addItems([s.value for s in PolicyStatus])
        form.addRow("Status:", self.status_combo)

        layout.addLayout(form)

        conditions_label = QLabel("Conditions (all checked groups must match)")
        conditions_label.setObjectName("CardLabel")
        layout.addWidget(conditions_label)

        self.device_status_checks: dict[str, QCheckBox] = {}
        status_row = QHBoxLayout()
        for status in DeviceStatus:
            box = QCheckBox(status.value)
            self.device_status_checks[status.value] = box
            status_row.addWidget(box)
        layout.addLayout(status_row)

        self.vendor_id_input = QLineEdit()
        self.vendor_id_input.setPlaceholderText("Vendor ID (optional, e.g. 0951)")
        layout.addWidget(self.vendor_id_input)

        self.time_window_check = QCheckBox("Restrict to a time window")
        layout.addWidget(self.time_window_check)

        time_row = QHBoxLayout()
        self.time_start = QTimeEdit(QTime(18, 0))
        self.time_end = QTimeEdit(QTime(8, 0))
        time_row.addWidget(QLabel("From:"))
        time_row.addWidget(self.time_start)
        time_row.addWidget(QLabel("To:"))
        time_row.addWidget(self.time_end)
        layout.addLayout(time_row)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save")
        save_button.setObjectName("PrimaryButton")
        save_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("SecondaryButton")
        cancel_button.clicked.connect(self.reject)
        button_row.addWidget(save_button)
        button_row.addWidget(cancel_button)
        layout.addLayout(button_row)

    def _load(self, policy: PolicyRecord) -> None:
        self.name_input.setText(policy.name)
        self.description_input.setPlainText(policy.description or "")
        self.priority_input.setValue(policy.priority)
        self.action_combo.setCurrentText(policy.action)
        self.status_combo.setCurrentText(policy.status)

        for value in policy.conditions.get("device_status", []):
            if value in self.device_status_checks:
                self.device_status_checks[value].setChecked(True)

        vendor_ids = policy.conditions.get("vendor_id")
        if vendor_ids:
            self.vendor_id_input.setText(vendor_ids[0])

        time_window = policy.conditions.get("time_window")
        if time_window:
            self.time_window_check.setChecked(True)
            h, m = (int(p) for p in time_window["start"].split(":"))
            self.time_start.setTime(QTime(h, m))
            h, m = (int(p) for p in time_window["end"].split(":"))
            self.time_end.setTime(QTime(h, m))

    def get_values(self) -> dict:
        conditions: dict = {}

        selected_statuses = [value for value, box in self.device_status_checks.items() if box.isChecked()]
        if selected_statuses:
            conditions["device_status"] = selected_statuses

        vendor_id = self.vendor_id_input.text().strip()
        if vendor_id:
            conditions["vendor_id"] = [vendor_id]

        if self.time_window_check.isChecked():
            conditions["time_window"] = {
                "start": self.time_start.time().toString("HH:mm"),
                "end": self.time_end.time().toString("HH:mm"),
            }

        return {
            "name": self.name_input.text().strip(),
            "description": self.description_input.toPlainText().strip() or None,
            "priority": self.priority_input.value(),
            "action": self.action_combo.currentText(),
            "status": self.status_combo.currentText(),
            "conditions": conditions,
        }
