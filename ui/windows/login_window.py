"""
Login dialog (Section 7 / Section 17).

This is a real authentication screen wired to app.security.auth.AuthService
- not a mock. It handles the same failure modes AuthService can raise:
invalid credentials, disabled account, locked account, and does not leak
which case occurred beyond what AuthService itself decides to disclose.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QWidget, QSpacerItem, QSizePolicy,
)

from app.core.exceptions import AuthenticationError
from app.security.auth import AuthService, AuthenticatedUser
from app.config.constants import APP_TITLE


class LoginDialog(QDialog):
    """
    Modal login dialog. On acceptance, self.authenticated_user holds the
    AuthenticatedUser returned by AuthService.authenticate().
    """

    def __init__(self, auth_service: AuthService, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._auth_service = auth_service
        self.authenticated_user: Optional[AuthenticatedUser] = None

        self.setWindowTitle("Sign in")
        self.setModal(True)
        self.setFixedSize(380, 340)
        self.setObjectName("Card")

        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(6)

        title = QLabel("USB Security System")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        subtitle = QLabel(APP_TITLE)
        subtitle.setObjectName("PlaceholderNotice")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        layout.addSpacerItem(QSpacerItem(0, 18, QSizePolicy.Minimum, QSizePolicy.Fixed))

        username_label = QLabel("Username")
        username_label.setObjectName("CardLabel")
        layout.addWidget(username_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.returnPressed.connect(self._focus_password)
        layout.addWidget(self.username_input)

        layout.addSpacerItem(QSpacerItem(0, 10, QSizePolicy.Minimum, QSizePolicy.Fixed))

        password_label = QLabel("Password")
        password_label.setObjectName("CardLabel")
        layout.addWidget(password_label)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self._attempt_login)
        layout.addWidget(self.password_input)

        self.error_label = QLabel("")
        self.error_label.setObjectName("ErrorLabel")
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)

        layout.addSpacerItem(QSpacerItem(0, 14, QSizePolicy.Minimum, QSizePolicy.Expanding))

        button_row = QHBoxLayout()
        self.login_button = QPushButton("Sign in")
        self.login_button.setObjectName("PrimaryButton")
        self.login_button.clicked.connect(self._attempt_login)
        button_row.addWidget(self.login_button)
        layout.addLayout(button_row)

        self.username_input.setFocus()

    def _focus_password(self) -> None:
        self.password_input.setFocus()

    def _attempt_login(self) -> None:
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            self._show_error("Enter both a username and password.")
            return

        self.login_button.setEnabled(False)
        try:
            self.authenticated_user = self._auth_service.authenticate(username, password)
            self.accept()
        except AuthenticationError as exc:
            self._show_error(str(exc))
            self.password_input.clear()
            self.password_input.setFocus()
        finally:
            self.login_button.setEnabled(True)

    def _show_error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.setVisible(True)
