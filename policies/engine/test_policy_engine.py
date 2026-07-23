from pathlib import Path

from policies.engine.policy_engine import (
    build_not_applicable_verdict,
    evaluate,
    is_control_applicable,
    load_control,
    _get_field,
)

CONTROLS_DIR = Path(__file__).resolve().parents[1] / "controls"

CONTROL = {
    "control_id": "SA-IOT-002",
    "title": "No default or hard-coded credentials",
    "saudi_source": [{"framework": "CGIoT-1:2024", "reference": "2-2-2"}],
    "severity": "high",
    "conditions": {
        "fail": {"field": "observations.default_creds", "op": "equals", "value": True},
        "partial": None,
        "pass": {"field": "observations.default_creds", "op": "equals", "value": False},
        "inconclusive": {"when": "evidence_missing_or_low_confidence"},
    },
    "remediation": "Force a unique strong password on first boot.",
}


def _evidence(default_creds):
    return {
        "evidence_id": "EV-2026-07-08-0007",
        "device_id": "device-insecure",
        "timestamp": "2026-07-08T10:15:32Z",
        "observations": {"default_creds": default_creds},
    }


def test_get_field_resolves_dotted_path():
    assert _get_field({"observations": {"default_creds": True}}, "observations.default_creds") is True


def test_get_field_missing_path_returns_none():
    assert _get_field({"observations": {}}, "observations.missing") is None


def test_fail_condition_matches_when_default_creds_true():
    verdict = evaluate(CONTROL, _evidence(True))
    assert verdict["status"] == "FAIL"
    assert verdict["matched"] == "fail"


def test_pass_condition_matches_when_default_creds_false():
    verdict = evaluate(CONTROL, _evidence(False))
    assert verdict["status"] == "PASS"
    assert verdict["matched"] == "pass"


def test_saudi_source_formatted_correctly():
    verdict = evaluate(CONTROL, _evidence(True))
    assert verdict["saudi_source"] == "CGIoT-1:2024 §2-2-2"


def test_fail_checked_before_pass_when_both_would_match_a_permissive_control():
    permissive = dict(CONTROL)
    permissive["conditions"] = {
        "fail": {"field": "observations.default_creds", "op": "in", "value": [True, False]},
        "partial": None,
        "pass": {"field": "observations.default_creds", "op": "equals", "value": False},
        "inconclusive": None,
    }
    verdict = evaluate(permissive, _evidence(False))
    assert verdict["matched"] == "fail"  # fail is checked first, per spec ordering


def test_inconclusive_when_nothing_matches():
    no_match_control = dict(CONTROL)
    no_match_control["conditions"] = {
        "fail": {"field": "observations.nonexistent", "op": "equals", "value": True},
        "partial": None,
        "pass": {"field": "observations.nonexistent", "op": "equals", "value": False},
        "inconclusive": {"when": "evidence_missing_or_low_confidence"},
    }
    verdict = evaluate(no_match_control, _evidence(True))
    assert verdict["status"] == "INCONCLUSIVE"


def test_not_contains_op():
    control = dict(CONTROL)
    control["conditions"] = {
        "fail": {"field": "observations.open_ports", "op": "contains", "value": 23},
        "partial": None,
        "pass": {"field": "observations.open_ports", "op": "not_contains", "value": 23},
        "inconclusive": {"when": "evidence_missing_or_low_confidence"},
    }
    evidence_with_telnet = {**_evidence(None), "observations": {"open_ports": [23, 80]}}
    evidence_without_telnet = {**_evidence(None), "observations": {"open_ports": [80]}}
    assert evaluate(control, evidence_with_telnet)["status"] == "FAIL"
    assert evaluate(control, evidence_without_telnet)["status"] == "PASS"


def test_sa_iot_003_real_control_reproduces_historical_verdicts_via_open_ports():
    # SA-IOT-003 used to key on a boolean observations.telnet_open field that
    # scan_tests.py no longer emits; it was migrated to open_ports contains/
    # not_contains 23 instead. Both fields co-existed in the real committed
    # Day-2 evidence, so this must reproduce the exact same historical
    # verdicts (EV-2026-07-08-0013 -> PASS, EV-2026-07-08-0014 -> FAIL).
    control = load_control(str(CONTROLS_DIR / "SA-IOT-003.yaml"))
    passing_evidence = {**_evidence(None), "observations": {"open_ports": [80]}}
    failing_evidence = {**_evidence(None), "observations": {"open_ports": [23]}}
    assert evaluate(control, passing_evidence)["status"] == "PASS"
    assert evaluate(control, failing_evidence)["status"] == "FAIL"


# ---------------------------------------------------------------------------
# Collector failure -> INCONCLUSIVE, never silence and never FAIL
# ---------------------------------------------------------------------------


def test_collector_error_produces_inconclusive_before_any_condition_runs():
    # Even though default_creds is unset (which alone would already trip the
    # missing-field inconclusive path), the collector_error flag must be
    # checked first and gives its own distinct reason.
    evidence = {**_evidence(None), "observations": {"collector_error": True, "error_detail": "command timed out after 30s"}}
    verdict = evaluate(CONTROL, evidence)
    assert verdict["status"] == "INCONCLUSIVE"
    assert "collector failed" in verdict["reason"]
    assert "timed out" in verdict["reason"]


def test_collector_error_is_never_treated_as_fail_even_when_fail_condition_would_match():
    # A failed collector must never be auto-scored as FAIL just because its
    # (empty/garbage) observations happen to satisfy a fail condition.
    evidence = {**_evidence(True), "observations": {"default_creds": True, "collector_error": True}}
    verdict = evaluate(CONTROL, evidence)
    assert verdict["status"] == "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# The "when" mechanism is real, not dead code
# ---------------------------------------------------------------------------


def test_low_confidence_evidence_triggers_the_when_inconclusive_path_even_if_a_condition_would_match():
    evidence = {**_evidence(True), "confidence": "low"}
    verdict = evaluate(CONTROL, evidence)
    assert verdict["status"] == "INCONCLUSIVE"
    assert verdict["reason"] == "when: evidence_missing_or_low_confidence"


def test_high_confidence_evidence_does_not_trigger_the_when_path():
    evidence = {**_evidence(True), "confidence": "high"}
    verdict = evaluate(CONTROL, evidence)
    assert verdict["status"] == "FAIL"


# ---------------------------------------------------------------------------
# NOT_APPLICABLE
# ---------------------------------------------------------------------------


def test_is_control_applicable_true_when_a_registered_service_matches():
    control = load_control(str(CONTROLS_DIR / "SA-IOT-004.yaml"))  # requires TEST-MQTT-OPEN
    assert is_control_applicable(control, [{"service_type": "mqtt"}]) is True


def test_is_control_applicable_false_when_no_registered_service_matches():
    control = load_control(str(CONTROLS_DIR / "SA-IOT-004.yaml"))  # requires TEST-MQTT-OPEN
    assert is_control_applicable(control, [{"service_type": "http"}]) is False


def test_is_control_applicable_false_for_a_device_with_no_services_at_all():
    control = load_control(str(CONTROLS_DIR / "SA-IOT-005.yaml"))
    assert is_control_applicable(control, []) is False


def test_is_control_applicable_true_when_the_required_test_has_no_automated_collector():
    # SA-IOT-001 requires TEST-DEVICE-ID, which has no entry in SCAN_CATALOG
    # at all (never wired into Run Scan) - regression: this must NOT be
    # treated as "doesn't apply to this device" (which would wrongly mark
    # every device NOT_APPLICABLE for a control that's simply not automated
    # yet), it must stay possibly-applicable so the control is left
    # unassessed instead.
    control = load_control(str(CONTROLS_DIR / "SA-IOT-001.yaml"))
    assert is_control_applicable(control, [{"service_type": "http"}]) is True
    assert is_control_applicable(control, []) is True


def test_build_not_applicable_verdict_has_no_evidence_and_the_right_status():
    control = load_control(str(CONTROLS_DIR / "SA-IOT-005.yaml"))
    verdict = build_not_applicable_verdict(control, "device-http-only", "2026-07-22T00:00:00Z")
    assert verdict["status"] == "NOT_APPLICABLE"
    assert verdict["matched"] == "not_applicable"
    assert verdict["evidence_ids"] == []
    assert verdict["device_id"] == "device-http-only"
