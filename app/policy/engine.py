"""
Policy evaluation engine (Section 12).

Deterministic evaluation order: active policies are evaluated in
ascending priority order (lower number = higher priority = evaluated
first), with ties broken by id (creation order) so evaluation is
reproducible given the same policy set. The FIRST matching policy wins;
evaluation stops there (Section 12: "Use a deterministic policy
evaluation order").

If no policy matches - which should not normally happen given the
seeded defaults cover every DeviceStatus - the engine fails closed
(default action = BLOCK) rather than silently allowing an unrecognized
device, and records why.

A policy whose conditions are malformed is skipped (with a warning
logged) rather than crashing the whole evaluation for every device
(Section 20).
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.engine import Engine

from app.core.enums import PolicyAction
from app.core.exceptions import PolicyEvaluationError
from app.policy.conditions import matches
from app.policy.repository import list_policies

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PolicyDecision:
    action: str  # PolicyAction value
    matched_policy_id: Optional[int]
    matched_policy_name: Optional[str]
    reason: str


def evaluate(context: dict, now: Optional[dt.datetime] = None, engine: Optional[Engine] = None) -> PolicyDecision:
    """
    Evaluate `context` (see app.policy.conditions.matches for expected
    keys) against all ACTIVE policies, in priority order.
    """
    now = now or dt.datetime.utcnow()
    policies = list_policies(active_only=True, engine=engine)

    for policy in policies:
        try:
            if matches(policy.conditions, context, now=now):
                return PolicyDecision(
                    action=policy.action,
                    matched_policy_id=policy.id,
                    matched_policy_name=policy.name,
                    reason=f"Matched policy '{policy.name}' (priority {policy.priority}).",
                )
        except PolicyEvaluationError as exc:
            logger.warning(f"Skipping policy '{policy.name}' (id={policy.id}) due to invalid conditions: {exc}")
            continue

    return PolicyDecision(
        action=PolicyAction.BLOCK.value,
        matched_policy_id=None,
        matched_policy_name=None,
        reason="No active policy matched this device; failing closed (default-deny).",
    )
