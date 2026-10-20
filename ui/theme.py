"""
Application theme: a dark, professional cybersecurity-dashboard look
(Section 16/17: "do not make the interface look like a generic student
CRUD application").

Palette:
    Background   - near-black navy, not pure black (less harsh)
    Surface      - slightly lighter panels for cards/sidebar
    Accent       - cyan, used for active nav / primary actions
    Success      - green, for AUTHORIZED / ALLOWED / TRUSTED states
    Warning      - amber, for UNKNOWN / pending states
    Danger       - red, for BLOCKED / UNAUTHORIZED / CRITICAL alerts
    Text         - off-white primary text, muted gray secondary text
"""

from __future__ import annotations

# --- Palette ---------------------------------------------------------
BG_PRIMARY = "#0B0F14"
BG_SURFACE = "#131A22"
BG_SURFACE_ALT = "#182029"
BG_SIDEBAR = "#0E141B"

BORDER = "#243040"

TEXT_PRIMARY = "#E6EDF3"
TEXT_SECONDARY = "#8B98A5"
TEXT_MUTED = "#5B6672"

ACCENT = "#3FD0FF"
ACCENT_DIM = "#1B5A6E"

SUCCESS = "#3FE07A"
WARNING = "#FFC24B"
DANGER = "#FF5C5C"
CRITICAL = "#FF3B3B"

# Status -> color mapping, used across device tables, alerts, badges.
STATUS_COLORS = {
    "TRUSTED": SUCCESS,
    "AUTHORIZED": SUCCESS,
    "ALLOWED": SUCCESS,
    "BLOCKED": DANGER,
    "UNAUTHORIZED": DANGER,
    "BLOCKING_FAILED": CRITICAL,
    "UNKNOWN": WARNING,
    "TEMPORARY": WARNING,
    "DETECTED": ACCENT,
    "REMOVED": TEXT_MUTED,
}

SEVERITY_COLORS = {
    "LOW": TEXT_SECONDARY,
    "MEDIUM": WARNING,
    "HIGH": DANGER,
    "CRITICAL": CRITICAL,
}


def status_color(status: str) -> str:
    return STATUS_COLORS.get(status, TEXT_SECONDARY)


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, TEXT_SECONDARY)


# --- Global stylesheet -------------------------------------------------
STYLESHEET = f"""
QWidget {{
    background-color: {BG_PRIMARY};
    color: {TEXT_PRIMARY};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}}

QMainWindow {{
    background-color: {BG_PRIMARY};
}}

/* --- Sidebar --- */
#Sidebar {{
    background-color: {BG_SIDEBAR};
    border-right: 1px solid {BORDER};
}}

#SidebarTitle {{
    color: {ACCENT};
    font-size: 15px;
    font-weight: 600;
    padding: 18px 16px 6px 16px;
}}

#SidebarSubtitle {{
    color: {TEXT_MUTED};
    font-size: 10px;
    padding: 0px 16px 16px 16px;
}}

QPushButton#NavButton {{
    background-color: transparent;
    color: {TEXT_SECONDARY};
    border: none;
    text-align: left;
    padding: 10px 18px;
    font-size: 13px;
    border-left: 3px solid transparent;
}}

QPushButton#NavButton:hover {{
    background-color: {BG_SURFACE};
    color: {TEXT_PRIMARY};
}}

QPushButton#NavButton:checked {{
    background-color: {BG_SURFACE};
    color: {ACCENT};
    border-left: 3px solid {ACCENT};
    font-weight: 600;
}}

/* --- Top bar --- */
#TopBar {{
    background-color: {BG_SURFACE};
    border-bottom: 1px solid {BORDER};
}}

#TopBarTitle {{
    color: {TEXT_PRIMARY};
    font-size: 14px;
    font-weight: 600;
}}

#UserBadge {{
    background-color: {BG_SURFACE_ALT};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 6px 12px;
}}

/* --- Cards --- */
#Card {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}

#CardLabel {{
    color: {TEXT_SECONDARY};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
}}

#CardValue {{
    color: {TEXT_PRIMARY};
    font-size: 28px;
    font-weight: 700;
}}

#SectionTitle {{
    color: {TEXT_PRIMARY};
    font-size: 16px;
    font-weight: 600;
    padding: 4px 0px;
}}

#PlaceholderNotice {{
    color: {TEXT_MUTED};
    font-size: 12px;
    font-style: italic;
}}

/* --- Inputs / buttons --- */
QLineEdit {{
    background-color: {BG_SURFACE_ALT};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 8px 10px;
}}

QLineEdit:focus {{
    border: 1px solid {ACCENT};
}}

QPushButton#PrimaryButton {{
    background-color: {ACCENT};
    color: #001018;
    border: none;
    border-radius: 4px;
    padding: 9px 18px;
    font-weight: 600;
}}

QPushButton#PrimaryButton:hover {{
    background-color: #63DBFF;
}}

QPushButton#PrimaryButton:disabled {{
    background-color: {ACCENT_DIM};
    color: {TEXT_MUTED};
}}

QPushButton#SecondaryButton {{
    background-color: transparent;
    color: {TEXT_SECONDARY};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 9px 18px;
}}

QPushButton#SecondaryButton:hover {{
    color: {TEXT_PRIMARY};
    border: 1px solid {TEXT_SECONDARY};
}}

#ErrorLabel {{
    color: {DANGER};
    font-size: 12px;
}}

QTableWidget {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    gridline-color: {BORDER};
    selection-background-color: {ACCENT_DIM};
}}

QHeaderView::section {{
    background-color: {BG_SURFACE_ALT};
    color: {TEXT_SECONDARY};
    padding: 6px;
    border: none;
    border-bottom: 1px solid {BORDER};
    font-weight: 600;
}}

QScrollBar:vertical {{
    background: {BG_PRIMARY};
    width: 10px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 24px;
}}
"""
