from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REAL_CONTROLS_DIR = str(Path(__file__).resolve().parents[3] / "policies" / "controls")

EVIDENCE_DEFAULT_CREDS_FAIL = {
    "evidence_id": "EV-2026-07-08-9010",
    "device_id": "device-insecure",
    "test_id": "TEST-AUTH-DEFAULT-CREDS",
    "tool": "curl",
    "tool_version": "8.9.1",
    "command": "curl POST login",
    "timestamp": "2026-07-08T08:06:42Z",
    "finding": "Default creds accepted",
    "observations": {"default_creds": True},
    "raw_output_path": "document-store/raw/EV-2026-07-08-9010.txt",
    "confidence": "high",
    "sha256": "a" * 64,
}


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("CONTROLS_DIR", REAL_CONTROLS_DIR)
    from main import app
    return TestClient(app)


def test_recompute_creates_a_verdict_for_matching_evidence(client):
    client.post("/evidence", json=EVIDENCE_DEFAULT_CREDS_FAIL)

    response = client.post("/verdicts/recompute")
    assert response.status_code == 200
    body = response.json()
    assert body["created"] == 1
    assert body["verdicts"][0]["control_id"] == "SA-IOT-002"
    assert body["verdicts"][0]["status"] == "FAIL"

    verdicts = client.get("/verdicts").json()
    assert len(verdicts) == 1


def test_recompute_is_idempotent_no_duplicates_on_second_call(client):
    client.post("/evidence", json=EVIDENCE_DEFAULT_CREDS_FAIL)

    first = client.post("/verdicts/recompute")
    assert first.json()["created"] == 1

    second = client.post("/verdicts/recompute")
    assert second.status_code == 200
    assert second.json()["created"] == 0

    verdicts = client.get("/verdicts").json()
    assert len(verdicts) == 1


def test_recompute_only_generates_for_evidence_matching_a_control(client):
    unrelated = dict(EVIDENCE_DEFAULT_CREDS_FAIL, evidence_id="EV-2026-07-08-9011", test_id="TEST-DOES-NOT-MAP")
    client.post("/evidence", json=unrelated)

    response = client.post("/verdicts/recompute")
    assert response.json()["created"] == 0


def _register_device(client, device_id, service_type, port):
    return client.post(
        "/devices",
        json={
            "device_id": device_id, "display_name": device_id, "tier": "unknown",
            "host": device_id,
            "services": [{"service_type": service_type, "port": port}],
        },
    )


def test_recompute_marks_not_applicable_for_a_device_with_no_matching_service(client):
    # SA-IOT-004 requires TEST-MQTT-OPEN; a device with only an http service
    # can never satisfy that, and has no evidence for it at all.
    _register_device(client, "http-only-cam", "http", 80)

    response = client.post("/verdicts/recompute")
    body = response.json()
    verdicts = [v for v in body["verdicts"] if v["device_id"] == "http-only-cam"]
    sa_iot_004 = next(v for v in verdicts if v["control_id"] == "SA-IOT-004")
    assert sa_iot_004["status"] == "NOT_APPLICABLE"
    assert sa_iot_004["evidence_ids"] == []


def test_recompute_leaves_a_control_with_no_automated_collector_unassessed(client):
    # SA-IOT-001 requires TEST-DEVICE-ID, which has no SCAN_CATALOG entry at
    # all - regression: this must stay unassessed (no verdict at all), not
    # be marked NOT_APPLICABLE, since an absent collector says nothing about
    # whether the control actually applies to this device.
    _register_device(client, "any-cam", "http", 80)

    response = client.post("/verdicts/recompute")
    body = response.json()
    sa_iot_001 = [v for v in body["verdicts"] if v["device_id"] == "any-cam" and v["control_id"] == "SA-IOT-001"]
    assert sa_iot_001 == []


def test_recompute_does_not_mark_not_applicable_when_a_service_could_apply(client):
    # This device HAS an mqtt service - SA-IOT-004 is applicable, just not
    # tested yet, which must stay unassessed rather than NOT_APPLICABLE.
    _register_device(client, "mqtt-cam", "mqtt", 1883)

    response = client.post("/verdicts/recompute")
    body = response.json()
    sa_iot_004_verdicts = [
        v for v in body["verdicts"] if v["device_id"] == "mqtt-cam" and v["control_id"] == "SA-IOT-004"
    ]
    assert sa_iot_004_verdicts == []


def test_recompute_turns_a_collector_failure_into_an_inconclusive_verdict(client):
    failed_evidence = dict(
        EVIDENCE_DEFAULT_CREDS_FAIL,
        evidence_id="EV-2026-07-08-9012",
        finding="Collector execution failed: command timed out after 30s",
        observations={"collector_error": True, "error_detail": "command timed out after 30s"},
        confidence="low",
    )
    client.post("/evidence", json=failed_evidence)

    response = client.post("/verdicts/recompute")
    body = response.json()
    assert body["created"] == 1
    assert body["verdicts"][0]["status"] == "INCONCLUSIVE"
    assert "collector failed" in body["verdicts"][0]["reason"]


def test_recompute_detects_conflicting_evidence_and_prefers_automated(client):
    document_says_ok = dict(
        EVIDENCE_DEFAULT_CREDS_FAIL,
        evidence_id="EV-2026-07-08-9013",
        observations={"default_creds": False},
        source_type="document",
        timestamp="2026-07-08T08:00:00Z",
    )
    capture_says_fail = dict(
        EVIDENCE_DEFAULT_CREDS_FAIL,
        evidence_id="EV-2026-07-08-9014",
        observations={"default_creds": True},
        source_type="automated",
        timestamp="2026-07-08T09:00:00Z",
    )
    client.post("/evidence", json=document_says_ok)
    client.post("/evidence", json=capture_says_fail)

    response = client.post("/verdicts/recompute")
    body = response.json()
    assert body["created"] == 1
    verdict = body["verdicts"][0]
    assert verdict["conflict_detected"] is True
    assert verdict["status"] == "FAIL"  # the automated evidence won
    assert set(verdict["evidence_ids"]) == {"EV-2026-07-08-9013", "EV-2026-07-08-9014"}
