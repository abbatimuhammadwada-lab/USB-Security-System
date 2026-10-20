"""Detached DTO for policies - same pattern as app/devices/dto.py."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PolicyRecord:
    id: int
    name: str
    description: Optional[str]
    priority: int
    conditions: dict
    action: str
    status: str
    created_by: Optional[int]
    created_at: dt.datetime
    updated_at: dt.datetime

    def conditions_summary(self) -> str:
        if not self.conditions:
            return "Matches all devices"
        parts = []
        for key, value in self.conditions.items():
            parts.append(f"{key}={value}")
        return "; ".join(parts)
