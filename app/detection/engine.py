"""
Intrusion detection orchestrator: runs every rule from rules.py against
one connection event and returns every signal that fired (zero or more).

Detection is deliberately separate from alerting (Phase 9 persists these
signals as security_alerts rows and surfaces them in the UI) and from
enforcement (Phase 7 already decided ALLOW/BLOCK before this runs) -
this module only observes and reports patterns, consistent with
Section 13's framing as a detection engine, not a decision-maker.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy.engine import Engine

from app.detection.rules import (
    check_unknown_device, check_blacklisted_device, check_policy_violation,
    check_repeated_unauthorized_attempts, check_rapid_connect_disconnect, check_after_hours,
)
from app.detection.signals import IntrusionSignal
from app.devices.dto import DeviceRecord
from app.policy.engine import PolicyDecision


def analyze_connection(
    device: DeviceRecord,
    event_timestamp: dt.datetime,
    decision: Optional[PolicyDecision] = None,
    engine: Optional[Engine] = None,
) -> list[IntrusionSignal]:
    signals: list[IntrusionSignal] = []

    for signal in (
        check_unknown_device(device),
        check_blacklisted_device(device),
        check_policy_violation(device, decision),
        check_repeated_unauthorized_attempts(device.id, engine=engine, now=event_timestamp),
        check_rapid_connect_disconnect(device.id, engine=engine, now=event_timestamp),
        check_after_hours(device, event_timestamp, engine=engine),
    ):
        if signal is not None:
            signals.append(signal)

    return signals
