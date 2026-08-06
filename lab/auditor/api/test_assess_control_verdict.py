from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REAL_CONTROLS_DIR = str(Path(__file__).resolve().parents[3] / "policies" / "controls")

EVIDENCE_DEFAULT_CREDS_FAIL = {
    "evidence_id": "EV-2026-07-08-9020",
    "device_id": "device-insecure",
    "test_id": "TEST-AUTH-DEFAULT-CREDS",
    "tool": "curl",
    "tool_version": "8.9.1",
    "command": "curl POST login",
    "timestamp": "2026-07-08T08:06:42Z",
    "finding": "Default creds accepted",
    "observations": {"default_creds": True},
    "raw_output_path": "document-store/raw/EV-2026-07-08-9020.txt",
    "confidence": "high",
    "sha256": "a" * 64,
}


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("CONTROLS_DIR", REAL_CONTROLS_DIR)
    from main import app
    return TestClient(app)


def _register_device(client, device_id, service_type, port):
    return client.post(
        "/devices",
        json={
            "device_id": device_id, "display_name": device_id, "tier": "unknown",
            "host": device_id,
            "services": [{"service_type": service_type, "port": port}],
        },
    )


def test_assess_computes_and_records_a_verdict_from_evidence(client):
    _register_device(client, "device-insecure", "http", 80)
    client.post("/evidence", json=EVIDENCE_DEFAULT_CREDS_FAIL)

    response = client.post("/devices/device-insecure/controls/SA-IOT-002/assess")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["control_id"] == "SA-IOT-002"
    assert body["status"] == "FAIL"
    assert "EV-2026-07-08-9020" in body["evidence_ids"]

    # The verdict was actually persisted.
    verdicts = client.get("/verdicts").json()
    assert any(v["verdict_id"] == body["verdict_id"] for v in verdicts)


def test_assess_404_for_unknown_device(client):
    assert client.post("/devices/nope/controls/SA-IOT-002/assess").status_code == 404


def test_assess_404_for_unknown_control(client):
    _register_device(client, "device-insecure", "http", 80)
    assert client.post("/devices/device-insecure/controls/SA-IOT-999/assess").status_code == 404


def test_assess_400_when_applicable_but_no_evidence(client):
    # SA-IOT-004 requires TEST-MQTT-OPEN; this device has an mqtt service (so
    # the control applies) but no evidence yet - nothing to assess.
    _register_device(client, "mqtt-cam", "mqtt", 1883)
    response = client.post("/devices/mqtt-cam/controls/SA-IOT-004/assess")
    assert response.status_code == 400
    assert "run" in response.json()["detail"].lower()


def test_assess_400_names_test_device_id_now_that_it_has_a_collector(client):
    # SA-IOT-001 requires TEST-DEVICE-ID, which spent most of this project's
    # life with no SCAN_CATALOG entry (so the 400 had to say "manual only").
    # It has a real collector now, so the message must name it like any other
    # runnable required test - the old wording would send an auditor to do by
    # hand something the product can actually run.
    _register_device(client, "device-insecure", "http", 80)
    response = client.post("/devices/device-insecure/controls/SA-IOT-001/assess")
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "TEST-DEVICE-ID" in detail
    assert "run" in detail.lower()


def test_assess_400_explains_manual_only_control_without_a_collector(client, monkeypatch):
    # The manual-only branch still has to work for the next control written
    # before its collector exists. No real SA-IOT-* control is manual-only any
    # more, so this reproduces the condition by hiding TEST-DEVICE-ID from the
    # catalog rather than by asserting a fact about the catalog that is no
    # longer true.
    from policies.catalog import scan_tests

    catalog_without_device_id = {
        k: v for k, v in scan_tests.SCAN_CATALOG.items() if k != "TEST-DEVICE-ID"
    }
    monkeypatch.setattr(scan_tests, "SCAN_CATALOG", catalog_without_device_id)
    import main
    monkeypatch.setattr(main, "SCAN_CATALOG", catalog_without_device_id)

    _register_device(client, "device-insecure", "http", 80)
    response = client.post("/devices/device-insecure/controls/SA-IOT-001/assess")
    assert response.status_code == 400
    detail = response.json()["detail"].lower()
    assert "no automated collector" in detail
    assert "test-device-id" not in detail  # never names an unrunnable test


def test_assess_marks_not_applicable_when_control_cannot_apply(client):
    # An http-only device can never satisfy SA-IOT-004 (needs mqtt).
    _register_device(client, "http-only-cam", "http", 80)
    response = client.post("/devices/http-only-cam/controls/SA-IOT-004/assess")
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "NOT_APPLICABLE"


def test_assess_uses_the_auditor_chosen_severity(client):
    _register_device(client, "device-insecure", "http", 80)
    client.post("/evidence", json=EVIDENCE_DEFAULT_CREDS_FAIL)

    response = client.post(
        "/devices/device-insecure/controls/SA-IOT-002/assess", json={"severity": "low"}
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "FAIL"  # status is still evidence-computed
    assert body["severity"] == "low"  # but severity is the auditor's choice


def test_assess_defaults_severity_to_the_control_when_not_chosen(client):
    _register_device(client, "device-insecure", "http", 80)
    client.post("/evidence", json=EVIDENCE_DEFAULT_CREDS_FAIL)

    body = client.post("/devices/device-insecure/controls/SA-IOT-002/assess").json()
    # No override -> the control's catalogued severity is used (a real value).
    assert body["severity"] in ("low", "medium", "high", "critical")


def test_assess_rejects_an_invalid_severity(client):
    _register_device(client, "device-insecure", "http", 80)
    client.post("/evidence", json=EVIDENCE_DEFAULT_CREDS_FAIL)

    response = client.post(
        "/devices/device-insecure/controls/SA-IOT-002/assess", json={"severity": "catastrophic"}
    )
    assert response.status_code == 400


def test_assess_always_records_a_fresh_verdict(client):
    # Unlike recompute (idempotent), an explicit assess always produces a new
    # verdict for the pair, even when nothing has changed.
    _register_device(client, "device-insecure", "http", 80)
    client.post("/evidence", json=EVIDENCE_DEFAULT_CREDS_FAIL)

    first = client.post("/devices/device-insecure/controls/SA-IOT-002/assess").json()
    second = client.post("/devices/device-insecure/controls/SA-IOT-002/assess").json()
    assert first["verdict_id"] != second["verdict_id"]
    assert len(client.get("/verdicts").json()) == 2
