"""
Reusable dashboard stat card (Section 16: TOTAL USB DEVICES, AUTHORIZED
DEVICES, BLOCKED DEVICES, etc). Purely presentational - the numeric
value is passed in by whichever page uses it, once real data sources
exist (Phase 6+ device registry, Phase 9 alerts). In Phase 4 pages pass
0 with a placeholder note, since no data source is wired yet - this
widget never fabricates a number.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel

from ui.theme import TEXT_PRIMARY


class StatCard(QWidget):
    def __init__(self, label: str, value: str = "0", accent_color: Optional[str] = None, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumHeight(96)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(6)

        self.label_widget = QLabel(label.upper())
        self.label_widget.setObjectName("CardLabel")
        layout.addWidget(self.label_widget)

        self.value_widget = QLabel(value)
        self.value_widget.setObjectName("CardValue")
        if accent_color:
            self.value_widget.setStyleSheet(f"color: {accent_color};")
        layout.addWidget(self.value_widget)

        layout.addStretch(1)

    def set_value(self, value: str) -> None:
        self.value_widget.setText(value)
