"""
Centralized application configuration.

Loads values from environment variables (via a .env file in development,
or real environment variables in production/packaged deployments). No
secrets or credentials are hardcoded here - see Section 25 / Section 7.
"""

from __future__ import annotations

import os
import sys
import platform
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
# BASE_DIR is the project root regardless of whether the app is run from
# source or from a PyInstaller-frozen executable (Phase 13 will extend this).
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent.parent.parent

ENV_FILE = BASE_DIR / ".env"
if ENV_FILE.exists():
    load_dotenv(ENV_FILE)

DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "data" / "reports"

for directory in (DATA_DIR, LOGS_DIR, REPORTS_DIR):
    directory.mkdir(parents=True, exist_ok=True)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # --- Application identity ---
    app_name: str = "USB Device Intrusion Detection, Access Control and Audit Logging System"
    app_short_name: str = "USB Security System"
    version: str = "0.1.0"
    app_env: str = field(default_factory=lambda: os.getenv("APP_ENV", "development"))

    # --- Platform ---
    is_windows: bool = field(default_factory=lambda: platform.system() == "Windows")
    platform_name: str = field(default_factory=platform.system)
    computer_name: str = field(default_factory=platform.node)

    # --- Paths ---
    base_dir: Path = BASE_DIR
    data_dir: Path = DATA_DIR
    logs_dir: Path = LOGS_DIR
    reports_dir: Path = REPORTS_DIR

    # --- Database ---
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL", f"sqlite:///{(DATA_DIR / 'usb_security.db').as_posix()}"
        )
    )

    # --- Logging ---
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    # --- Security / session policy (Phase 3 will consume these) ---
    session_timeout_minutes: int = field(
        default_factory=lambda: _env_int("SESSION_TIMEOUT_MINUTES", 30)
    )
    max_failed_logins: int = field(
        default_factory=lambda: _env_int("MAX_FAILED_LOGINS", 5)
    )
    lockout_minutes: int = field(
        default_factory=lambda: _env_int("LOCKOUT_MINUTES", 15)
    )
    password_hash_scheme: str = field(
        default_factory=lambda: os.getenv("PASSWORD_HASH_SCHEME", "argon2id")
    )

    # --- USB / detection behavior (Phase 5+ will consume these) ---
    simulation_mode: bool = field(
        default_factory=lambda: _env_bool("SIMULATION_MODE", True)
    )
    unauthorized_attempt_threshold: int = field(
        default_factory=lambda: _env_int("UNAUTHORIZED_ATTEMPT_THRESHOLD", 5)
    )
    unauthorized_attempt_window_minutes: int = field(
        default_factory=lambda: _env_int("UNAUTHORIZED_ATTEMPT_WINDOW_MINUTES", 10)
    )

    def summary(self) -> str:
        """Human-readable startup summary (no secrets included)."""
        lines = [
            f"{self.app_short_name} v{self.version}",
            f"Environment      : {self.app_env}",
            f"Platform         : {self.platform_name}",
            f"Windows detected : {self.is_windows}",
            f"Computer name    : {self.computer_name}",
            f"Database URL     : {self.database_url}",
            f"Data directory   : {self.data_dir}",
            f"Logs directory   : {self.logs_dir}",
            f"Simulation mode  : {self.simulation_mode}",
        ]
        return "\n".join(lines)


settings = Settings()
