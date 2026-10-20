"""Detection signal produced by a rule-based check (Section 13)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class IntrusionSignal:
    alert_type: str  # AlertType enum value
    severity: str  # AlertSeverity enum value
    description: str
    device_id: Optional[int] = None
