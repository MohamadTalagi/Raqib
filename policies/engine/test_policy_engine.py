from pathlib import Path

from policies.engine.policy_engine import evaluate, load_control, _get_field

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
