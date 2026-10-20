"""
Policy condition matching (Section 12).

A policy's `conditions` column is a JSON object. Every key present must
match for the policy to apply (AND semantics across keys); a missing or
empty conditions object matches everything, which is how a catch-all/
default policy is expressed.

Supported condition keys:
    device_status   : list[str]   - matches USBDevice.status
    device_class    : list[str]   - matches the classified device class
    vendor_id       : list[str]   - matches USBDevice.vendor_id (case-insensitive)
    product_id      : list[str]   - matches USBDevice.product_id (case-insensitive)
    fingerprint_hash: list[str]   - matches the device's fingerprint hash exactly
    computer_name   : list[str]   - matches the reporting computer's name
    username        : list[str]   - matches the currently signed-in operator, if any
    time_window     : {"start": "HH:MM", "end": "HH:MM"}
                       - matches if the evaluation time falls in this
                         window; supports overnight windows where
                         start > end (e.g. 18:00-08:00 covers after-hours)

Any other key, or a malformed value for a known key, raises
PolicyEvaluationError - the engine catches this per-policy (Section 20:
one bad policy must not crash the whole evaluation) and skips that
policy rather than silently ignoring the mistake.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from app.core.exceptions import PolicyEvaluationError

_KNOWN_LIST_KEYS = {"device_status", "device_class", "vendor_id", "product_id", "fingerprint_hash", "computer_name", "username"}


def _match_list_condition(condition_values: Any, context_value: Any, key: str) -> bool:
    if not isinstance(condition_values, list) or not all(isinstance(v, str) for v in condition_values):
        raise PolicyEvaluationError(f"Condition '{key}' must be a list of strings.")
    if context_value is None:
        return False
    context_str = str(context_value).strip().lower()
    return context_str in {str(v).strip().lower() for v in condition_values}


def _match_time_window(condition_value: Any, now: dt.datetime) -> bool:
    if not isinstance(condition_value, dict) or "start" not in condition_value or "end" not in condition_value:
        raise PolicyEvaluationError("Condition 'time_window' must be an object with 'start' and 'end' (HH:MM).")
    try:
        start_h, start_m = (int(part) for part in condition_value["start"].split(":"))
        end_h, end_m = (int(part) for part in condition_value["end"].split(":"))
    except (ValueError, AttributeError) as exc:
        raise PolicyEvaluationError(
            f"Condition 'time_window' has invalid start/end format (expected HH:MM): {exc}"
        ) from exc

    start = dt.time(start_h, start_m)
    end = dt.time(end_h, end_m)
    current = now.time()

    if start <= end:
        return start <= current <= end
    # Overnight window (e.g. 18:00 - 08:00): true if current is after
    # start OR before end.
    return current >= start or current <= end


def matches(conditions: dict, context: dict, now: dt.datetime | None = None) -> bool:
    """
    Return True if every key in `conditions` matches the corresponding
    value in `context`. An empty/missing conditions dict always matches.

    `context` expected keys: device_status, device_class, vendor_id,
    product_id, fingerprint_hash, computer_name, username.
    """
    if not conditions:
        return True

    now = now or dt.datetime.utcnow()

    for key, value in conditions.items():
        if key in _KNOWN_LIST_KEYS:
            if not _match_list_condition(value, context.get(key), key):
                return False
        elif key == "time_window":
            if not _match_time_window(value, now):
                return False
        else:
            raise PolicyEvaluationError(f"Unknown policy condition key: '{key}'.")

    return True


def validate_conditions_schema(conditions: dict) -> None:
    """
    Raise PolicyEvaluationError if `conditions` is structurally invalid,
    without needing a real context to check against. Used by the policy
    repository to reject bad input at creation/edit time rather than
    waiting to discover the problem during live evaluation.
    """
    dummy_context = {
        "device_status": "UNKNOWN", "device_class": "Unknown device", "vendor_id": "0000",
        "product_id": "0000", "fingerprint_hash": "x" * 64, "computer_name": "TEST",
        "username": "test",
    }
    matches(conditions, dummy_context)  # raises PolicyEvaluationError on structural issues
