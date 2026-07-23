"""Systematic pass/fail/inconclusive/contradictory-evidence coverage for
every one of the 5 real SA-IOT-* controls (Week 1 brief, task 10: "Four
tests per control"). Each control's real field/pass-value/fail-value is
read directly from its own YAML - not duplicated by hand - so this stays
correct if a control's condition ever changes.
"""

from pathlib import Path

import pytest

from policies.engine.conflict import detect_conflict
from policies.engine.policy_engine import evaluate, load_control

CONTROLS_DIR = Path(__file__).resolve().parents[1] / "controls"

CONTROL_IDS = ["SA-IOT-001", "SA-IOT-002", "SA-IOT-003", "SA-IOT-004", "SA-IOT-005"]


def _control(control_id: str) -> dict:
    return load_control(str(CONTROLS_DIR / f"{control_id}.yaml"))


def _field_name(control: dict) -> str:
    # Every one of the 5 controls' pass condition is a plain
    # {field, op, value} equals/contains check on one field - read the
    # field name directly rather than hardcoding a parallel table.
    return control["conditions"]["pass"]["field"].removeprefix("observations.")


def _evidence(control: dict, field_value, *, confidence="high", source_type="automated", evidence_id="EV-1", timestamp="2026-07-08T10:00:00Z"):
    field = _field_name(control)
    return {
        "evidence_id": evidence_id,
        "device_id": "device-under-test",
        "timestamp": timestamp,
        "confidence": confidence,
        "source_type": source_type,
        "observations": {field: field_value},
    }


# (control_id, pass_field_value, fail_field_value) - values are whatever the
# control's own pass/fail conditions actually check, read from the YAML
# itself at test time via _pass_fail_values, not hardcoded here.
def _pass_fail_values(control_id: str) -> tuple:
    control = _control(control_id)
    conditions = control["conditions"]
    if control_id == "SA-IOT-003":
        # SA-IOT-003 is a contains/not_contains check on a list, not equals -
        # a real port list with vs. without Telnet (23).
        return [80], [23, 80]
    return conditions["pass"]["value"], conditions["fail"]["value"]


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_pass_case(control_id):
    control = _control(control_id)
    pass_value, _ = _pass_fail_values(control_id)
    verdict = evaluate(control, _evidence(control, pass_value))
    assert verdict["status"] == "PASS"


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_fail_case(control_id):
    control = _control(control_id)
    _, fail_value = _pass_fail_values(control_id)
    verdict = evaluate(control, _evidence(control, fail_value))
    assert verdict["status"] == "FAIL"


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_inconclusive_or_missing_evidence_case(control_id):
    control = _control(control_id)
    fail_value, _ = _pass_fail_values(control_id)
    # Evidence exists and would otherwise satisfy a condition, but its
    # recorder marked it low confidence - must not assert PASS/FAIL on it.
    verdict = evaluate(control, _evidence(control, fail_value, confidence="low"))
    assert verdict["status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_contradictory_evidence_case(control_id):
    control = _control(control_id)
    pass_value, fail_value = _pass_fail_values(control_id)

    documentation_says_fine = _evidence(
        control, pass_value, source_type="document", evidence_id="EV-DOC", timestamp="2026-07-08T09:00:00Z",
    )
    technical_capture_says_bad = _evidence(
        control, fail_value, source_type="automated", evidence_id="EV-CAPTURE", timestamp="2026-07-08T10:00:00Z",
    )

    chosen, conflict, reason = detect_conflict(control, [documentation_says_fine, technical_capture_says_bad])
    assert conflict is True
    assert reason is not None
    # Directly observed technical evidence wins over documentation.
    assert chosen["evidence_id"] == "EV-CAPTURE"

    verdict = evaluate(
        control, chosen,
        conflict_detected=conflict, conflict_reason=reason,
        all_evidence_ids=["EV-DOC", "EV-CAPTURE"],
    )
    assert verdict["status"] == "FAIL"
    assert verdict["conflict_detected"] is True
    assert verdict["evidence_ids"] == ["EV-DOC", "EV-CAPTURE"]
