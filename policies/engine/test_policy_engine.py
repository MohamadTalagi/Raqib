from policies.engine.policy_engine import evaluate, _get_field

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
