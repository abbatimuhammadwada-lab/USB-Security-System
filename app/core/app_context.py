"""
Lightweight application context.

This holds process-wide state that later phases will populate:
the current authenticated user/session (Phase 3), the database session
factory (Phase 2), and the simulation-mode flag surfaced to the UI and
audit log (Phase 24). It intentionally does very little in Phase 1 -
it exists now so later phases have one obvious place to wire things in
instead of scattering globals across modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.config.settings import settings
from app.utils.privileges import is_running_as_admin


@dataclass
class AppContext:
    is_admin_privileged: bool = field(default_factory=is_running_as_admin)
    simulation_mode: bool = field(default_factory=lambda: settings.simulation_mode)
    current_user: Optional[object] = None  # populated in Phase 3
    db_session_factory: Optional[object] = None  # populated in Phase 2

    def describe(self) -> str:
        return (
            f"AppContext(admin_privileged={self.is_admin_privileged}, "
            f"simulation_mode={self.simulation_mode}, "
            f"authenticated={self.current_user is not None})"
        )


app_context = AppContext()
