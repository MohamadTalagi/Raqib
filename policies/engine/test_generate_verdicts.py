import json

from policies.engine.generate_verdicts import generate_verdicts


def _write_evidence(path, evidence_id, test_id, device_id, observations):
    record = {
        "evidence_id": evidence_id,
        "device_id": device_id,
        "test_id": test_id,
        "tool": "curl",
        "tool_version": "8.9.1",
        "command": "curl ...",
        "timestamp": "2026-07-08T10:15:32Z",
        "finding": "test finding",
        "observations": observations,
        "raw_output_path": "document-store/raw/x.txt",
        "confidence": "high",
        "sha256": "a" * 64,
    }
    path.write_text(json.dumps(record))
    return record


def _write_control(path, contents):
    path.write_text(contents)


CONTROL_YAML = """
control_id: SA-IOT-002
title: No default or hard-coded credentials
saudi_source:
  - framework: CGIoT-1:2024
    reference: "2-2-2"
applicability:
  device_type: [smart-camera]
required_evidence:
  - test_id: TEST-AUTH-DEFAULT-CREDS
automated_test_ids: [TEST-AUTH-DEFAULT-CREDS]
severity: high
conditions:
  pass: { field: "observations.default_creds", op: "equals", value: false }
  fail: { field: "observations.default_creds", op: "equals", value: true }
  partial: null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: "Force a unique strong password on first boot."
"""


def test_generate_verdicts_produces_fail_and_pass_across_devices(tmp_path):
    evidence_dir = tmp_path / "evidence"
    controls_dir = tmp_path / "controls"
    output_dir = tmp_path / "verdicts"
    evidence_dir.mkdir()
    controls_dir.mkdir()

    _write_control(controls_dir / "SA-IOT-002.yaml", CONTROL_YAML)
    _write_evidence(evidence_dir / "EV-1.json", "EV-1", "TEST-AUTH-DEFAULT-CREDS", "device-insecure", {"default_creds": True})
    _write_evidence(evidence_dir / "EV-2.json", "EV-2", "TEST-AUTH-DEFAULT-CREDS", "device-hardened", {"default_creds": False})

    verdicts = generate_verdicts(evidence_dir, controls_dir, output_dir)

    statuses_by_device = {v["device_id"]: v["status"] for v in verdicts}
    assert statuses_by_device["device-insecure"] == "FAIL"
    assert statuses_by_device["device-hardened"] == "PASS"
    assert len(list(output_dir.glob("VD-*.json"))) == 2
