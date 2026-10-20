"""Detached DTO for security alerts - same pattern as devices/policy DTOs."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class AlertRecord:
    id: int
    severity: str
    alert_type: str
    device_id: Optional[int]
    device_name: Optional[str]
    computer_name: Optional[str]
    description: str
    is_read: bool
    is_resolved: bool
    resolved_by: Optional[int]
    resolved_at: Optional[dt.datetime]
    created_at: dt.datetime
