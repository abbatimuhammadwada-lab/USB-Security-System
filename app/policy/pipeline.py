"""
Connection processing pipeline: the single entry point that turns a raw
USBDeviceInfo detection event into a fully evaluated, (attempted-)
enforced, and audited outcome.

Sequence for a CONNECTED event:
    1. app.devices.repository.record_device_event() - persist the
       device/fingerprint/event rows (Phase 6). Initial event result is
       DETECTED.
    2. Build a policy-evaluation context from the now-known device.
    3. app.policy.engine.evaluate() - find the first matching active
       policy (Phase 7).
    4. Apply the decision:
         ALLOW     -> event.result = ALLOWED
         BLOCK     -> attempt real enforcement (app.enforcement); event.result
                       becomes BLOCKED or BLOCKING_FAILED depending on
                       whether the attempt actually succeeded - never
                       claim BLOCKED without having tried.
         ALERT     -> event.result stays DETECTED; audited distinctly.
                       Actual SecurityAlert rows arrive in Phase 9.
         LOG_ONLY  -> event.result stays DETECTED; audited distinctly.
    5. Write an ACCESS_ALLOWED / ACCESS_DENIED audit entry reflecting
       the final decision.

REMOVED events skip policy evaluation entirely (nothing to authorize)
and are returned as-is from record_device_event().
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.engine import Engine

from app.core.enums import PolicyAction, EnforcementResult, AuditEventType, AuditSeverity
from app.database.engine import session_scope
from app.devices import repository as device_repo
from app.devices.dto import DeviceEventRecord, DeviceRecord
from app.detection.engine import analyze_connection
from app.detection.signals import IntrusionSignal
from app.alerts.repository import create_alerts_from_signals
from app.enforcement.windows_enforcement import attempt_block_device
from app.logging.audit import write_audit_log
from app.policy.engine import evaluate, PolicyDecision
from app.usb.device_info import USBDeviceInfo

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConnectionOutcome:
    event: Optional[DeviceEventRecord]
    device: Optional[DeviceRecord]
    decision: Optional[PolicyDecision]
    final_result: Optional[str]  # EnforcementResult value, mirrors event.result after processing
    signals: list = None  # list[IntrusionSignal] - detection signals raised for this event


def _build_context(device: DeviceRecord, info: USBDeviceInfo, username: Optional[str]) -> dict:
    return {
        "device_status": device.status,
        "device_class": device.device_class,
        "vendor_id": device.vendor_id,
        "product_id": device.product_id,
        "fingerprint_hash": None,  # not denormalized onto DeviceRecord; add if a policy needs it
        "computer_name": info.computer_name,
        "username": username,
    }


def process_connection_event(
    info: USBDeviceInfo,
    username: Optional[str] = None,
    engine: Optional[Engine] = None,
) -> ConnectionOutcome:
    """
    Full pipeline for one USBDeviceInfo event. Safe to call for both
    CONNECTED and REMOVED events - REMOVED short-circuits after the
    registry write, since there is nothing to authorize.
    """
    event = device_repo.record_device_event(info, engine=engine)
    if event is None:
        # Could not even fingerprint the device - already audited inside
        # record_device_event(). Nothing further to evaluate.
        return ConnectionOutcome(event=None, device=None, decision=None, final_result=None, signals=[])

    if info.is_remove():
        return ConnectionOutcome(event=event, device=None, decision=None, final_result=event.result, signals=[])

    device = device_repo.get_device(event.device_id, engine=engine)
    if device is None:  # pragma: no cover - defensive, should be unreachable
        return ConnectionOutcome(event=event, device=None, decision=None, final_result=event.result, signals=[])

    context = _build_context(device, info, username)
    decision = evaluate(context, engine=engine)

    final_result = _apply_decision(event, device, decision, engine=engine)

    signals = analyze_connection(device, info.timestamp, decision=decision, engine=engine)
    if signals:
        create_alerts_from_signals(signals, computer_name=info.computer_name, engine=engine)

    return ConnectionOutcome(event=event, device=device, decision=decision, final_result=final_result, signals=signals)


def _apply_decision(
    event: DeviceEventRecord, device: DeviceRecord, decision: PolicyDecision, engine: Optional[Engine] = None,
) -> str:
    if decision.action == PolicyAction.ALLOW.value:
        result = EnforcementResult.ALLOWED.value
        device_repo.update_event_result(event.id, result, engine=engine)
        with session_scope(engine=engine) as session:
            write_audit_log(
                session, AuditEventType.ACCESS_ALLOWED,
                f"Access allowed for '{device.display_name()}': {decision.reason}",
                device_id=device.id, result=result, severity=AuditSeverity.INFO,
            )
        return result

    if decision.action == PolicyAction.BLOCK.value:
        outcome = attempt_block_device(device.pnp_device_id)
        device_repo.update_event_result(event.id, outcome.result, engine=engine)
        with session_scope(engine=engine) as session:
            write_audit_log(
                session, AuditEventType.ACCESS_DENIED,
                f"Access denied for '{device.display_name()}': {decision.reason} "
                f"Enforcement outcome: {outcome.reason}",
                device_id=device.id, result=outcome.result,
                severity=AuditSeverity.HIGH if outcome.result == EnforcementResult.BLOCKED.value else AuditSeverity.CRITICAL,
            )
        return outcome.result

    if decision.action == PolicyAction.ALERT.value:
        with session_scope(engine=engine) as session:
            write_audit_log(
                session, AuditEventType.ACCESS_DENIED,
                f"Policy flagged '{device.display_name()}' for review (ALERT, no enforcement "
                f"attempted): {decision.reason} Security alert generation arrives in Phase 9.",
                device_id=device.id, result=event.result, severity=AuditSeverity.WARNING,
            )
        return event.result  # unchanged (still DETECTED)

    # LOG_ONLY
    with session_scope(engine=engine) as session:
        write_audit_log(
            session, AuditEventType.ACCESS_ALLOWED,
            f"Policy recorded '{device.display_name()}' with no access change (LOG_ONLY): {decision.reason}",
            device_id=device.id, result=event.result, severity=AuditSeverity.INFO,
        )
    return event.result
