import responses

from policies.engine.generate_verdicts import generate_verdicts

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
