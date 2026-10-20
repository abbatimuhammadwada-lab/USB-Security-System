"""
Policy repository (Section 12): CRUD for named access-control policies,
with full audit trail (POLICY_CREATED / POLICY_CHANGED / POLICY_DELETED).

Permission enforcement (Section 6: only Administrators may create/modify/
delete policies) is the caller's responsibility, matching the pattern
used in app/devices/repository.py - this module enforces data integrity
(conditions schema, unique priority ordering is NOT required - ties are
broken deterministically by id) but not RBAC.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Optional

from sqlalchemy import select
from sqlalchemy.engine import Engine

from app.core.enums import PolicyStatus, AuditEventType, AuditSeverity
from app.core.exceptions import PolicyEvaluationError
from app.database.engine import session_scope
from app.database.models import Policy
from app.logging.audit import write_audit_log
from app.policy.conditions import validate_conditions_schema
from app.policy.dto import PolicyRecord


def _to_record(policy: Policy) -> PolicyRecord:
    try:
        conditions = json.loads(policy.conditions) if policy.conditions else {}
    except (json.JSONDecodeError, TypeError):
        conditions = {}
    return PolicyRecord(
        id=policy.id, name=policy.name, description=policy.description,
        priority=policy.priority, conditions=conditions, action=policy.action,
        status=policy.status, created_by=policy.created_by,
        created_at=policy.created_at, updated_at=policy.updated_at,
    )


def create_policy(
    name: str, action: str, created_by: Optional[int],
    description: Optional[str] = None, priority: int = 100,
    conditions: Optional[dict] = None, status: str = PolicyStatus.ACTIVE.value,
    engine: Optional[Engine] = None,
) -> PolicyRecord:
    conditions = conditions or {}
    validate_conditions_schema(conditions)  # raises PolicyEvaluationError if malformed

    if not name or not name.strip():
        raise ValueError("Policy name must not be empty.")

    with session_scope(engine=engine) as session:
        policy = Policy(
            name=name.strip(), description=description, priority=priority,
            conditions=json.dumps(conditions), action=action, status=status,
            created_by=created_by,
        )
        session.add(policy)
        session.flush()

        write_audit_log(
            session, AuditEventType.POLICY_CREATED,
            f"Policy '{policy.name}' created (action={action}, priority={priority}).",
            user_id=created_by, result="ALLOWED", severity=AuditSeverity.INFO,
        )
        record = _to_record(policy)
    return record


def update_policy(
    policy_id: int, updated_by: Optional[int], engine: Optional[Engine] = None, **fields,
) -> PolicyRecord:
    """
    Update any subset of: name, description, priority, conditions
    (dict), action, status.
    """
    if "conditions" in fields and fields["conditions"] is not None:
        validate_conditions_schema(fields["conditions"])

    with session_scope(engine=engine) as session:
        policy = session.get(Policy, policy_id)
        if policy is None:
            raise ValueError(f"No policy with id={policy_id}")

        changes = []
        for field_name in ("name", "description", "priority", "action", "status"):
            if field_name in fields and fields[field_name] is not None:
                old_value = getattr(policy, field_name)
                new_value = fields[field_name]
                if old_value != new_value:
                    setattr(policy, field_name, new_value)
                    changes.append(f"{field_name}: {old_value!r} -> {new_value!r}")

        if "conditions" in fields and fields["conditions"] is not None:
            new_conditions_json = json.dumps(fields["conditions"])
            if policy.conditions != new_conditions_json:
                policy.conditions = new_conditions_json
                changes.append("conditions updated")

        policy.updated_at = dt.datetime.utcnow()

        write_audit_log(
            session, AuditEventType.POLICY_CHANGED,
            f"Policy '{policy.name}' updated: {'; '.join(changes) if changes else 'no fields changed'}.",
            user_id=updated_by, result="ALLOWED", severity=AuditSeverity.INFO,
        )
        record = _to_record(policy)
    return record


def delete_policy(policy_id: int, deleted_by: Optional[int], engine: Optional[Engine] = None) -> None:
    with session_scope(engine=engine) as session:
        policy = session.get(Policy, policy_id)
        if policy is None:
            raise ValueError(f"No policy with id={policy_id}")

        name = policy.name
        write_audit_log(
            session, AuditEventType.POLICY_DELETED,
            f"Policy '{name}' (id={policy_id}) deleted.",
            user_id=deleted_by, result="ALLOWED", severity=AuditSeverity.WARNING,
        )
        session.delete(policy)


def list_policies(active_only: bool = False, engine: Optional[Engine] = None) -> list[PolicyRecord]:
    with session_scope(engine=engine) as session:
        stmt = select(Policy).order_by(Policy.priority.asc(), Policy.id.asc())
        if active_only:
            stmt = stmt.where(Policy.status == PolicyStatus.ACTIVE.value)
        policies = session.scalars(stmt).all()
        return [_to_record(p) for p in policies]


def get_policy(policy_id: int, engine: Optional[Engine] = None) -> Optional[PolicyRecord]:
    with session_scope(engine=engine) as session:
        policy = session.get(Policy, policy_id)
        return _to_record(policy) if policy else None
