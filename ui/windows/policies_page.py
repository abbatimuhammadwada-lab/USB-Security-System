"""
Policies page (Section 12) - replaces the Phase 4 placeholder.

Every signed-in user can view the policy list (there's nothing
sensitive about policy names/conditions), but only users with
CREATE_POLICY/MODIFY_POLICY/DELETE_POLICY (Administrators - Section 6)
can create, edit, or delete a policy.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QMessageBox,
)
from PySide6.QtGui import QColor, QBrush

from app.core.exceptions import AuthorizationError, PolicyEvaluationError
from app.policy import repository as policy_repo
from app.policy.dto import PolicyRecord
from app.security.auth import AuthenticatedUser
from app.security.permissions import Permission, require_permission, has_permission
from ui.theme import ACCENT, DANGER, SUCCESS, WARNING, TEXT_SECONDARY
from ui.windows.policy_edit_dialog import PolicyEditDialog

_ACTION_COLORS = {"ALLOW": SUCCESS, "BLOCK": DANGER, "ALERT": WARNING, "LOG_ONLY": TEXT_SECONDARY}
_COLUMNS = ["Priority", "Name", "Action", "Status", "Conditions", "Updated"]


class PoliciesPage(QWidget):
    def __init__(self, user: AuthenticatedUser, engine=None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._user = user
        self._engine = engine
        self._policies: list[PolicyRecord] = []

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        header_row = QHBoxLayout()
        header = QLabel("Access Control Policies")
        header.setObjectName("SectionTitle")
        header_row.addWidget(header)
        header_row.addStretch(1)

        can_manage = has_permission(self._user.role, Permission.CREATE_POLICY)
        if can_manage:
            new_button = QPushButton("New Policy")
            new_button.setObjectName("PrimaryButton")
            new_button.clicked.connect(self._create_policy)
            header_row.addWidget(new_button)

        refresh_button = QPushButton("Refresh")
        refresh_button.setObjectName("SecondaryButton")
        refresh_button.clicked.connect(self.refresh)
        header_row.addWidget(refresh_button)
        layout.addLayout(header_row)

        note = QLabel(
            "Policies are evaluated in priority order (lowest number first); the first "
            "matching ACTIVE policy decides ALLOW/BLOCK/ALERT/LOG_ONLY for a connecting device."
        )
        note.setObjectName("PlaceholderNotice")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(QHeaderView.ResizeToContents)
        header_view.setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.itemSelectionChanged.connect(self._update_action_buttons)
        self.table.doubleClicked.connect(self._edit_selected)
        layout.addWidget(self.table, stretch=1)

        if can_manage:
            action_row = QHBoxLayout()
            self.edit_button = QPushButton("Edit")
            self.edit_button.setObjectName("SecondaryButton")
            self.edit_button.clicked.connect(self._edit_selected)
            self.delete_button = QPushButton("Delete")
            self.delete_button.setObjectName("SecondaryButton")
            self.delete_button.clicked.connect(self._delete_selected)
            for btn in (self.edit_button, self.delete_button):
                btn.setEnabled(False)
                action_row.addWidget(btn)
            action_row.addStretch(1)
            layout.addLayout(action_row)
        else:
            self.edit_button = None
            self.delete_button = None
            note2 = QLabel("Your role has read-only access to policies.")
            note2.setObjectName("PlaceholderNotice")
            layout.addWidget(note2)

    def refresh(self) -> None:
        self._policies = policy_repo.list_policies(engine=self._engine)
        self.table.setRowCount(len(self._policies))
        for row, policy in enumerate(self._policies):
            values = [
                str(policy.priority), policy.name, policy.action, policy.status,
                policy.conditions_summary(), str(policy.updated_at),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 2:
                    item.setForeground(QBrush(QColor(_ACTION_COLORS.get(policy.action, TEXT_SECONDARY))))
                if col == 3 and policy.status == "DISABLED":
                    item.setForeground(QBrush(QColor(TEXT_SECONDARY)))
                self.table.setItem(row, col, item)
        self._update_action_buttons()

    def _selected_policy(self) -> Optional[PolicyRecord]:
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not rows:
            return None
        row = rows[0].row()
        if row < 0 or row >= len(self._policies):
            return None
        return self._policies[row]

    def _update_action_buttons(self) -> None:
        if self.edit_button is None:
            return
        has_selection = self._selected_policy() is not None
        self.edit_button.setEnabled(has_selection)
        self.delete_button.setEnabled(has_selection)

    def _create_policy(self) -> None:
        dialog = PolicyEditDialog(parent=self)
        if dialog.exec() != PolicyEditDialog.Accepted:
            return
        values = dialog.get_values()
        if not values["name"]:
            QMessageBox.warning(self, "Missing name", "Policy name is required.")
            return
        try:
            require_permission(self._user.role, Permission.CREATE_POLICY)
            policy_repo.create_policy(
                values["name"], values["action"], self._user.id,
                description=values["description"], priority=values["priority"],
                conditions=values["conditions"], status=values["status"], engine=self._engine,
            )
        except (AuthorizationError, PolicyEvaluationError, ValueError) as exc:
            QMessageBox.warning(self, "Could not create policy", str(exc))
            return
        self.refresh()

    def _edit_selected(self) -> None:
        policy = self._selected_policy()
        if policy is None or self.edit_button is None:
            return
        dialog = PolicyEditDialog(policy=policy, parent=self)
        if dialog.exec() != PolicyEditDialog.Accepted:
            return
        values = dialog.get_values()
        try:
            require_permission(self._user.role, Permission.MODIFY_POLICY)
            policy_repo.update_policy(policy.id, self._user.id, engine=self._engine, **values)
        except (AuthorizationError, PolicyEvaluationError, ValueError) as exc:
            QMessageBox.warning(self, "Could not update policy", str(exc))
            return
        self.refresh()

    def _delete_selected(self) -> None:
        policy = self._selected_policy()
        if policy is None:
            return
        confirm = QMessageBox.question(
            self, "Delete policy", f"Delete policy '{policy.name}'? This cannot be undone."
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            require_permission(self._user.role, Permission.DELETE_POLICY)
            policy_repo.delete_policy(policy.id, self._user.id, engine=self._engine)
        except (AuthorizationError, ValueError) as exc:
            QMessageBox.warning(self, "Could not delete policy", str(exc))
            return
        self.refresh()
