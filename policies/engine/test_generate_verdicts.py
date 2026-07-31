from pathlib import Path

import responses

from policies.engine.generate_verdicts import generate_verdicts

CONTROLS_DIR = Path(__file__).resolve().parents[1] / "controls"

EVIDENCE_FAIL = {
    "evidence_id": "EV-2026-07-08-9001", "device_id": "device-insecure",
    "test_id": "TEST-AUTH-DEFAULT-CREDS", "tool": "curl", "tool_version": "8.9.1",
    "command": "curl POST login", "timestamp": "2026-07-08T08:06:42Z",
    "finding": "Default creds accepted", "observations": {"default_creds": True},
    "raw_output_path": "document-store/raw/EV-2026-07-08-9001.txt",
    "confidence": "high", "sha256": "a" * 64,
}
EVIDENCE_PASS = dict(
    EVIDENCE_FAIL, evidence_id="EV-2026-07-08-9002", device_id="device-hardened",
    observations={"default_creds": False},
)


@responses.activate
def test_generate_verdicts_produces_fail_and_pass_across_devices(tmp_path):
    api_url = "http://auditor-api:8000"
    responses.add(responses.GET, f"{api_url}/evidence", json=[EVIDENCE_FAIL, EVIDENCE_PASS])
    responses.add(responses.POST, f"{api_url}/verdicts", json={}, status=201)

    control_dir = tmp_path / "controls"
    control_dir.mkdir()
    (control_dir / "SA-IOT-002.yaml").write_text(
        """
control_id: SA-IOT-002
title: No default or hard-coded credentials
saudi_source:
  - framework: CGIoT-1:2024
    reference: "2-2-2"
    clause: "Prevent the users from using default and hard-coded passwords."
applicability:
  device_type: [smart-camera]
required_evidence:
  - test_id: TEST-AUTH-DEFAULT-CREDS
severity: high
conditions:
  fail:
    field: observations.default_creds
    op: equals
    value: true
  pass:
    field: observations.default_creds
    op: equals
    value: false
  partial: null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: Force password change on first boot
"""
    )

    verdicts = generate_verdicts(api_url=api_url, controls_dir=str(control_dir))

    statuses = {(v["device_id"]): v["status"] for v in verdicts}
    assert statuses["device-insecure"] == "FAIL"
    assert statuses["device-hardened"] == "PASS"

    post_calls = [c for c in responses.calls if c.request.method == "POST"]
    assert len(post_calls) == 2


def _evidence(evidence_id: str, test_id: str, observations: dict) -> dict:
    return {
        "evidence_id": evidence_id, "device_id": "device-partial", "test_id": test_id,
        "tool": "test-tool", "tool_version": "1.0.0", "command": "n/a",
        "timestamp": "2026-07-31T09:00:00Z", "finding": "synthetic evidence for the partial profile",
        "observations": observations, "raw_output_path": f"document-store/raw/{evidence_id}.txt",
        "confidence": "high", "sha256": "c" * 64,
    }


@responses.activate
def test_generate_verdicts_produces_a_mixed_result_for_device_partial(tmp_path):
    """Week 1 brief, task 10: 'one complete assessment test per device
    profile'. device-insecure (all-FAIL) and device-hardened (all-PASS) are
    already covered above; this closes the gap for device-partial, whose
    documented posture (CLAUDE.md's Task 0 device profile: Telnet removed,
    default password changed, HTTPS with a weak cert, MQTT still
    unencrypted) should produce a genuine mix of PASS and FAIL - not another
    all-one-way result - against the real, shipped SA-IOT-* controls
    (CONTROLS_DIR, the same real-controls convention test_controls_four_cases.py
    already established, not synthetic YAML)."""
    api_url = "http://auditor-api:8000"
    evidence_records = [
        _evidence("EV-2026-07-31-9001", "TEST-DEVICE-ID", {"device_identified": True}),
        _evidence("EV-2026-07-31-9002", "TEST-AUTH-DEFAULT-CREDS", {"default_creds": False}),
        _evidence("EV-2026-07-31-9003", "TEST-NET-PORTSCAN", {"open_ports": [80, 443]}),
        _evidence("EV-2026-07-31-9004", "TEST-MQTT-OPEN", {"mqtt_tls": False}),
        _evidence("EV-2026-07-31-9005", "TEST-TLS-CONFIG", {"weak_cipher": True}),
    ]
    responses.add(responses.GET, f"{api_url}/evidence", json=evidence_records)
    responses.add(responses.POST, f"{api_url}/verdicts", json={}, status=201)

    verdicts = generate_verdicts(api_url=api_url, controls_dir=str(CONTROLS_DIR))

    statuses = {v["control_id"]: v["status"] for v in verdicts}
    assert statuses["SA-IOT-001"] == "PASS"
    assert statuses["SA-IOT-002"] == "PASS"
    assert statuses["SA-IOT-003"] == "PASS"
    assert statuses["SA-IOT-004"] == "FAIL"
    assert statuses["SA-IOT-005"] == "FAIL"
    # The whole point: a real mix, not every control landing on the same side.
    assert {"PASS", "FAIL"} == set(statuses.values())
