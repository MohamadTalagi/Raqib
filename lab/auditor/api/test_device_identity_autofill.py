"""Regression tests for the TEST-DEVICE-ID auto-populate hook in
record_scan_job_evidence.

The hook writes real inventory data into `devices` as a side effect of an
auditor recording evidence, so the tests that matter most are the ones
proving it will NOT overwrite something a human typed. Those are the
assertions to be suspicious of if this file ever needs changing.
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    from main import app
    return TestClient(app)


DEVICE_INFO_OBSERVATIONS = {
    "device_identified": True,
    "vendor": "Hikvision",
    "model": "DS-2CD2143G2-I",
    "firmware_version": "V5.3.0 build 160530",
    "mac": "A4:14:37:00:11:22",
    "notes": ["identified"],
}


def _register_device(client, device_id="device-insecure", **extra):
    response = client.post(
        "/devices",
        json={
            "device_id": device_id, "display_name": device_id, "tier": "unknown",
            "host": device_id, "services": [{"service_type": "http", "port": 80}],
            **extra,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _run_device_id_job(client, device_id, observations):
    """Drives one TEST-DEVICE-ID job to `awaiting_finding` the way the worker
    does, then records a finding the way an auditor does."""
    job = client.post(
        "/scan-jobs", json={"device_id": device_id, "test_id": "TEST-DEVICE-ID"},
    ).json()
    patched = client.patch(
        f"/scan-jobs/{job['id']}",
        json={
            "status": "awaiting_finding", "tool": "curl", "tool_version": "curl 8.9.1",
            "command": f"curl -s http://{device_id}/api/device/info",
            "raw_output": "{}", "observations": observations,
        },
    )
    assert patched.status_code == 200, patched.text
    recorded = client.post(
        f"/scan-jobs/{job['id']}/record",
        json={"finding": "Device disclosed its identity.", "confidence": "high"},
    )
    assert recorded.status_code == 201, recorded.text
    return recorded.json()


def test_autofill_populates_an_empty_identity_and_marks_it_auto_detected(client):
    _register_device(client)
    assert client.get("/devices/device-insecure").json()["device"]["identity_source"] == "manual"

    _run_device_id_job(client, "device-insecure", DEVICE_INFO_OBSERVATIONS)

    device = client.get("/devices/device-insecure").json()["device"]
    assert device["vendor"] == "Hikvision"
    assert device["model"] == "DS-2CD2143G2-I"
    assert device["firmware_version"] == "V5.3.0 build 160530"
    assert device["identity_source"] == "auto_detected"


def test_autofill_never_overwrites_a_manually_set_vendor(client):
    # The single most important guarantee here: a human's inventory data wins.
    _register_device(client, vendor="Acme Corp (auditor-entered)")

    _run_device_id_job(client, "device-insecure", DEVICE_INFO_OBSERVATIONS)

    device = client.get("/devices/device-insecure").json()["device"]
    assert device["vendor"] == "Acme Corp (auditor-entered)"
    # Partial manual data means hands off entirely - not a blend of the two
    # under one ambiguous provenance flag.
    assert device["model"] is None
    assert device["firmware_version"] is None
    assert device["identity_source"] == "manual"


def test_autofill_does_not_fire_when_the_device_was_not_identified(client):
    _register_device(client)
    observations = {
        "device_identified": False, "vendor": "Hikvision", "model": None,
        "firmware_version": None, "mac": None, "notes": ["not identified"],
    }

    _run_device_id_job(client, "device-insecure", observations)

    device = client.get("/devices/device-insecure").json()["device"]
    assert device["vendor"] is None
    assert device["identity_source"] == "manual"


def test_autofill_is_scoped_to_test_device_id_evidence(client):
    # Another collector's evidence must never touch the devices row, even if
    # its observations happen to carry the same keys.
    _register_device(client)
    job = client.post(
        "/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-HTTP-HEADERS"},
    ).json()
    client.patch(
        f"/scan-jobs/{job['id']}",
        json={
            "status": "awaiting_finding", "tool": "curl", "tool_version": "curl 8.9.1",
            "command": "curl -sI http://device-insecure/", "raw_output": "HTTP/1.1 200 OK",
            "observations": DEVICE_INFO_OBSERVATIONS,
        },
    )
    recorded = client.post(
        f"/scan-jobs/{job['id']}/record",
        json={"finding": "Headers missing.", "confidence": "high"},
    )
    assert recorded.status_code == 201

    device = client.get("/devices/device-insecure").json()["device"]
    assert device["vendor"] is None
    assert device["identity_source"] == "manual"


def test_patching_an_identity_field_resets_identity_source_to_manual(client):
    _register_device(client)
    _run_device_id_job(client, "device-insecure", DEVICE_INFO_OBSERVATIONS)
    assert client.get("/devices/device-insecure").json()["device"]["identity_source"] == "auto_detected"

    patched = client.patch("/devices/device-insecure", json={"vendor": "Corrected By Auditor"})
    assert patched.status_code == 200, patched.text
    assert patched.json()["vendor"] == "Corrected By Auditor"
    assert patched.json()["identity_source"] == "manual"


def test_patching_a_non_identity_field_leaves_identity_source_alone(client):
    _register_device(client)
    _run_device_id_job(client, "device-insecure", DEVICE_INFO_OBSERVATIONS)

    patched = client.patch("/devices/device-insecure", json={"location": "Building 4"})
    assert patched.status_code == 200, patched.text
    assert patched.json()["identity_source"] == "auto_detected"


def test_identity_source_is_not_directly_patchable(client):
    # If a human could set this flag by hand, the "auto-detected, not
    # auditor-verified" badge would be lie-able.
    _register_device(client)
    response = client.patch("/devices/device-insecure", json={"identity_source": "auto_detected"})
    assert response.status_code == 400
    assert client.get("/devices/device-insecure").json()["device"]["identity_source"] == "manual"


def test_a_second_run_does_not_overwrite_a_corrected_value(client):
    _register_device(client)
    _run_device_id_job(client, "device-insecure", DEVICE_INFO_OBSERVATIONS)
    client.patch("/devices/device-insecure", json={"vendor": "Corrected By Auditor"})

    _run_device_id_job(client, "device-insecure", DEVICE_INFO_OBSERVATIONS)

    device = client.get("/devices/device-insecure").json()["device"]
    assert device["vendor"] == "Corrected By Auditor"
    assert device["identity_source"] == "manual"


def test_firmware_version_can_be_supplied_manually_at_registration(client):
    device = _register_device(client, firmware_version="1.2.3-typed-by-hand")
    assert device["firmware_version"] == "1.2.3-typed-by-hand"
    assert device["identity_source"] == "manual"


def test_device_list_and_detail_both_expose_the_new_fields(client):
    _register_device(client)
    listed = next(d for d in client.get("/devices").json() if d["device_id"] == "device-insecure")
    assert listed["firmware_version"] is None
    assert listed["identity_source"] == "manual"
    detail = client.get("/devices/device-insecure").json()["device"]
    assert "firmware_version" in detail
    assert "identity_source" in detail
