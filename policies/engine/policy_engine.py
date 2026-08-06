import json
import operator
from typing import Any, Optional

import yaml

OPS = {
    "equals": operator.eq,
    "not_equals": operator.ne,
    "in": lambda a, b: a in b if b is not None else False,
    "not_in": lambda a, b: a not in b if b is not None else True,
    "greater_than": lambda a, b: a is not None and a > b,
    "less_than": lambda a, b: a is not None and a < b,
    "contains": lambda a, b: b in a if a is not None else False,
    "not_contains": lambda a, b: b not in a if a is not None else True,
}

STATUS_MAP = {
    "fail": "FAIL", "partial": "PARTIAL", "pass": "PASS",
    "inconclusive": "INCONCLUSIVE", "not_applicable": "NOT_APPLICABLE",
}


def _get_field(record: dict, dotted_path: str) -> Any:
    value: Any = record
    for part in dotted_path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


def _condition_matches(evidence: dict, condition: Optional[dict]) -> bool:
    if not condition or "when" in condition:
        return False
    field = condition["field"]
    op = condition["op"]
    expected = condition["value"]
    actual = _get_field(evidence, field)
    return OPS[op](actual, expected)


def condition_matches(evidence: dict, condition: Optional[dict]) -> bool:
    """Public entry point for the {field, op, value} predicate this module
    already evaluates - reused as-is by policies/nca/finding_mappings.py so
    the NCA mapping layer has one predicate vocabulary instead of a second
    one invented from scratch."""
    return _condition_matches(evidence, condition)


def load_control(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_evidence(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _evidence_missing_or_low_confidence(control: dict, evidence: dict) -> bool:
    """The one WHEN_HANDLERS rule this project currently defines: evidence is
    too weak to trust a pass/fail verdict on, either because the recorder
    marked it low confidence, or because the specific field a pass/fail
    condition keys on simply isn't present in this evidence's observations."""
    if evidence.get("confidence") == "low":
        return True
    for key in ("pass", "fail"):
        condition = (control.get("conditions") or {}).get(key)
        if condition and not condition.get("when") and _get_field(evidence, condition["field"]) is None:
            return True
    return False


WHEN_HANDLERS = {
    "evidence_missing_or_low_confidence": _evidence_missing_or_low_confidence,
}


def _when_matches(when_key: str, control: dict, evidence: dict) -> bool:
    handler = WHEN_HANDLERS.get(when_key)
    return handler(control, evidence) if handler else False


def is_control_applicable(control: dict, device_services: list[dict]) -> bool:
    """True if at least one of the control's required_evidence test_ids could
    ever run against at least one of the device's registered services -
    reuses policies/catalog/scan_tests.py's own is_applicable() rather than
    the unused applicability.device_type field (which doesn't correspond to
    any column devices actually have).

    A required test_id with no automated collector at all (not in
    SCAN_CATALOG) tells us nothing about whether the control applies to this
    device - the honest answer is "not yet automated," not "doesn't apply,"
    so this returns True (meaning: don't treat it as inapplicable) rather
    than assuming an absent collector means the control can never apply.
    (SA-IOT-001's TEST-DEVICE-ID was the standing example of that case for
    most of this project's life; it now has a real collector, so SA-IOT-001
    resolves through the normal service-matching path below - which is what
    its own `limitations` field always said should happen: a device with no
    HTTP service evaluates to NOT_APPLICABLE.)"""
    from policies.catalog.scan_tests import SCAN_CATALOG, is_applicable

    test_ids = {req["test_id"] for req in control["required_evidence"]}
    if any(test_id not in SCAN_CATALOG for test_id in test_ids):
        return True
    for service in device_services:
        target = {"service_type": service.get("service_type")}
        if any(is_applicable(target, test_id) for test_id in test_ids):
            return True
    return False


def build_not_applicable_verdict(control: dict, device_id: str, timestamp: str, verdict_id: Optional[str] = None) -> dict:
    """A control with no evidence at all, because none of its required tests
    could ever apply to this device's registered services, is NOT_APPLICABLE -
    not silently unassessed and not INCONCLUSIVE (which implies a test was
    attempted and came back weak)."""
    saudi = control["saudi_source"][0]
    result = {
        "control_id": control["control_id"],
        "device_id": device_id,
        "status": "NOT_APPLICABLE",
        "severity": control["severity"],
        "evidence_ids": [],
        "matched": "not_applicable",
        "reason": "no required_evidence test_id applies to this device's registered services",
        "saudi_source": f"{saudi['framework']} §{saudi['reference']}",
        "remediation": control["remediation"],
        "timestamp": timestamp,
        "conflict_detected": False,
        "conflict_reason": None,
    }
    if verdict_id:
        result = {"verdict_id": verdict_id, **result}
    return result


def evaluate(
    control: dict,
    evidence: dict,
    verdict_id: Optional[str] = None,
    *,
    conflict_detected: bool = False,
    conflict_reason: Optional[str] = None,
    all_evidence_ids: Optional[list] = None,
) -> dict:
    """conflict_detected/conflict_reason/all_evidence_ids are supplied by the
    caller after running policies/engine/conflict.py's detect_conflict()
    against every evidence row relevant to this (device, control) pair -
    evaluate() itself always scores against exactly one (the already-chosen)
    evidence record, but the verdict still records every evidence id that was
    considered, not just the winner, per the brief's "record both evidence
    items" requirement."""
    observations = evidence.get("observations") or {}
    conditions = control["conditions"]

    inconclusive_condition = conditions.get("inconclusive") or {}
    when_key = inconclusive_condition.get("when")

    if observations.get("collector_error"):
        # A collector that failed to run at all (timeout, invalid target,
        # execution exception) must never silently produce nothing and must
        # never be treated as a FAIL either - it's INCONCLUSIVE, deterministically,
        # before any condition matching runs.
        matched = "inconclusive"
        reason = f"collector failed: {observations.get('error_detail', 'unknown error')}"
    elif when_key and _when_matches(when_key, control, evidence):
        # Confidence/missing-field gating runs BEFORE fail/partial/pass
        # matching, on purpose: evidence too weak to trust must never be
        # allowed to assert a PASS or FAIL just because its (possibly
        # garbage) observations happen to satisfy a condition.
        matched = "inconclusive"
        reason = f"when: {when_key}"
    else:
        matched = "inconclusive"
        reason = "no condition matched; evidence insufficient"
        for status in ("fail", "partial", "pass"):
            condition = conditions.get(status)
            if _condition_matches(evidence, condition):
                matched = status
                reason = f"{condition['field']} {condition['op']} {condition['value']}"
                break

    saudi = control["saudi_source"][0]
    result = {
        "control_id": control["control_id"],
        "device_id": evidence["device_id"],
        "status": STATUS_MAP[matched],
        "severity": control["severity"],
        "evidence_ids": all_evidence_ids if all_evidence_ids is not None else [evidence["evidence_id"]],
        "matched": matched,
        "reason": f"{reason} (conflicting evidence - see conflict_reason)" if conflict_detected else reason,
        "saudi_source": f"{saudi['framework']} §{saudi['reference']}",
        "remediation": control["remediation"],
        "timestamp": evidence["timestamp"],
        "conflict_detected": conflict_detected,
        "conflict_reason": conflict_reason,
    }
    if verdict_id:
        result = {"verdict_id": verdict_id, **result}
    return result
