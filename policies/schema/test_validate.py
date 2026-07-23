import pytest
from jsonschema import ValidationError
from policies.schema.validate import validate_evidence, validate_verdict, validate_control

VALID_EVIDENCE = {
    "evidence_id": "EV-2026-07-08-0007",
    "device_id": "device-insecure",
    "test_id": "TEST-NET-PORTSCAN",
    "tool": "nmap",
    "tool_version": "7.94",
    "command": "nmap -sV -p- device-insecure",
    "timestamp": "2026-07-08T10:15:32Z",
    "finding": "Telnet (23/tcp) open; plaintext management exposed",
    "observations": {"open_ports": [23, 80, 1883], "telnet_open": True},
    "raw_output_path": "document-store/raw/EV-2026-07-08-0007.txt",
    "confidence": "high",
    "sha256": "3f2a" + "0" * 60,
}

VALID_VERDICT = {
    "verdict_id": "VD-2026-07-08-0003",
    "control_id": "SA-IOT-002",
    "device_id": "device-insecure",
    "status": "FAIL",
    "severity": "high",
    "evidence_ids": ["EV-2026-07-08-0007"],
    "matched": "fail",
    "reason": "observations.default_creds == true",
    "saudi_source": "CGIoT-1:2024 §2-2-2",
    "remediation": "Force a unique strong password on first boot; remove all vendor defaults.",
    "timestamp": "2026-07-08T10:16:04Z",
}

VALID_CONTROL = {
    "control_id": "SA-IOT-002",
    "title": "No default or hard-coded credentials",
    "saudi_source": [{"framework": "CGIoT-1:2024", "reference": "2-2-2", "clause": "..."}],
    "applicability": {"device_type": ["smart-camera"]},
    "required_evidence": [{"test_id": "TEST-AUTH-DEFAULT-CREDS"}],
    "automated_test_ids": ["TEST-AUTH-DEFAULT-CREDS"],
    "severity": "high",
    "conditions": {
        "pass": {"field": "observations.default_creds", "op": "equals", "value": False},
        "fail": {"field": "observations.default_creds", "op": "equals", "value": True},
        "partial": None,
        "inconclusive": {"when": "evidence_missing_or_low_confidence"},
    },
    "remediation": "Force a unique strong password on first boot; remove all vendor defaults.",
    "version": "1.0.0",
    "limitations": "Only tries a fixed set of default credential pairs.",
}


def test_valid_evidence_passes():
    validate_evidence(VALID_EVIDENCE)  # should not raise


def test_evidence_missing_field_fails():
    with pytest.raises(ValidationError):
        validate_evidence({"evidence_id": "EV-2026-07-08-0007"})


def test_evidence_bad_confidence_enum_fails():
    bad = dict(VALID_EVIDENCE)
    bad["confidence"] = "extreme"
    with pytest.raises(ValidationError):
        validate_evidence(bad)


def test_evidence_bad_sha256_shape_fails():
    bad = dict(VALID_EVIDENCE)
    bad["sha256"] = "not-a-hash"
    with pytest.raises(ValidationError):
        validate_evidence(bad)


def test_valid_verdict_passes():
    validate_verdict(VALID_VERDICT)


def test_verdict_bad_status_enum_fails():
    bad = dict(VALID_VERDICT)
    bad["status"] = "MAYBE"
    with pytest.raises(ValidationError):
        validate_verdict(bad)


def test_valid_control_passes():
    validate_control(VALID_CONTROL)


def test_control_missing_conditions_fails():
    bad = dict(VALID_CONTROL)
    del bad["conditions"]
    with pytest.raises(ValidationError):
        validate_control(bad)
