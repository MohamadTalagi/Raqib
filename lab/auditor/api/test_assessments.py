from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REAL_CONTROLS_DIR = str(Path(__file__).resolve().parents[3] / "policies" / "controls")


@pytest.fixture
def client(postgres_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("CONTROLS_DIR", REAL_CONTROLS_DIR)
    # Without this, record-failure/record tests write real raw-output files
    # into the real document-store/raw/ directory (via the /work -> C:\work
    # junction) even though the database side is fully isolated to an
    # ephemeral test Postgres - confirmed live this session: it silently
    # overwrote a real evidence file's content. test_scan_jobs.py already
    # isolates this the same way; this file just hadn't caught up.
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    from main import app
    return TestClient(app)


def _register_device(client, device_id="cam-1", service_type="http", port=80):
    return client.post(
        "/devices",
        json={
            "device_id": device_id, "display_name": device_id, "tier": "unknown",
            "host": device_id,
            "services": [{"service_type": service_type, "port": port}],
        },
    )


def test_create_assessment_requires_device_id_and_test_ids(client):
    response = client.post("/assessments", json={"device_id": "cam-1"})
    assert response.status_code == 422


def test_create_assessment_creates_one_row_and_child_jobs(client):
    _register_device(client)
    response = client.post(
        "/assessments",
        json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS", "TEST-HTTP-HEADERS"]},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["device_id"] == "cam-1"
    assert body["status"] == "queued"
    assert len(body["jobs"]) == 2
    assert all(job["assessment_id"] == body["id"] for job in body["jobs"])
    assert body["errors"] == {}


def test_create_assessment_records_policy_version_from_matching_controls(client):
    _register_device(client)
    response = client.post(
        "/assessments", json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS"]},
    )
    # SA-IOT-002.yaml declares version: "1.0.0"
    assert response.json()["policy_version"] == "1.0.0"


def test_version_sort_key_orders_versions_numerically_not_lexicographically():
    from main import _version_sort_key

    assert sorted(["1.9.0", "1.10.0", "1.2.0"], key=_version_sort_key) == ["1.2.0", "1.9.0", "1.10.0"]
    # A malformed/non-numeric version never crashes the sort - it just
    # sorts after every well-formed one.
    assert sorted(["1.0.0", "not-a-version"], key=_version_sort_key) == ["1.0.0", "not-a-version"]


def test_create_assessment_picks_the_semantically_newest_version_not_the_lexicographically_last(
    postgres_url, monkeypatch, tmp_path
):
    # Regression: a plain string sort puts "1.9.0" after "1.10.0"
    # ("1" < "9" character-wise ignores that 10 > 9 numerically) - masked in
    # the real control catalog only because every control YAML happens to
    # be pinned at "1.0.0" today. Uses its own scratch CONTROLS_DIR (real
    # control YAMLs are all "1.0.0", so this can't be reproduced against
    # them) with two minimal synthetic controls.
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    controls_dir = tmp_path / "controls"
    controls_dir.mkdir()
    (controls_dir / "OLD.yaml").write_text(
        "control_id: OLD\nversion: \"1.9.0\"\nrequired_evidence:\n  - test_id: TEST-FAKE-A\n"
    )
    (controls_dir / "NEW.yaml").write_text(
        "control_id: NEW\nversion: \"1.10.0\"\nrequired_evidence:\n  - test_id: TEST-FAKE-B\n"
    )
    monkeypatch.setenv("CONTROLS_DIR", str(controls_dir))
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))

    # CONTROLS_DIR (unlike DATABASE_URL) is a module-level constant read
    # once at import time, not lazily per-request - if `main` was already
    # imported earlier in this test session (by another file's `client`
    # fixture), just setting the env var here has no effect on the
    # already-bound value. Patch the module attribute directly instead.
    import main as main_module
    monkeypatch.setattr(main_module, "CONTROLS_DIR", controls_dir)
    client = TestClient(main_module.app)
    _register_device(client)
    response = client.post(
        "/assessments", json={"device_id": "cam-1", "test_ids": ["TEST-FAKE-A", "TEST-FAKE-B"]},
    )
    assert response.json()["policy_version"] == "1.10.0"


def test_create_assessment_reports_per_test_errors_without_failing_the_whole_batch(client):
    _register_device(client, service_type="http", port=80)
    response = client.post(
        "/assessments",
        json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS", "TEST-MQTT-OPEN"]},
    )
    body = response.json()
    assert len(body["jobs"]) == 1  # only the applicable one was created
    assert "TEST-MQTT-OPEN" in body["errors"]


def test_get_assessment_includes_its_jobs(client):
    _register_device(client)
    created = client.post(
        "/assessments", json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS"]},
    ).json()

    response = client.get(f"/assessments/{created['id']}")
    assert response.status_code == 200
    assert len(response.json()["jobs"]) == 1


def test_get_unknown_assessment_is_404(client):
    assert client.get("/assessments/no-such-id").status_code == 404


def test_create_assessment_response_has_no_collector_versions_before_anything_runs(client):
    # tool/tool_version are only set once job_runner.py actually executes a
    # collector - honestly empty at creation time, never guessed.
    _register_device(client)
    created = client.post(
        "/assessments", json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS"]},
    ).json()
    assert created["collector_versions"] == []


def test_get_assessment_includes_deduplicated_collector_versions_once_jobs_have_run(client):
    _register_device(client)
    created = client.post(
        "/assessments",
        json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS", "TEST-HTTP-HEADERS"]},
    ).json()
    job_ids = [job["id"] for job in created["jobs"]]

    client.patch(
        f"/scan-jobs/{job_ids[0]}",
        json={"status": "awaiting_finding", "observations": {}, "tool": "curl", "tool_version": "8.5.0", "command": "curl ..."},
    )
    client.patch(
        f"/scan-jobs/{job_ids[1]}",
        json={"status": "awaiting_finding", "observations": {}, "tool": "curl", "tool_version": "8.5.0", "command": "curl ..."},
    )

    assessment = client.get(f"/assessments/{created['id']}").json()
    # Both jobs ran the same tool/version - deduplicated to one entry, not two.
    assert assessment["collector_versions"] == [{"tool": "curl", "tool_version": "8.5.0"}]


def test_assessment_status_becomes_completed_once_its_only_job_is_recorded(client):
    _register_device(client)
    created = client.post(
        "/assessments", json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS"]},
    ).json()
    job_id = created["jobs"][0]["id"]

    client.patch(
        f"/scan-jobs/{job_id}",
        json={
            "status": "awaiting_finding", "observations": {"default_creds": False},
            "tool": "curl", "tool_version": "8.5.0", "command": "curl ...", "raw_output": "ok",
        },
    )
    client.post(f"/scan-jobs/{job_id}/record", json={"finding": "no default creds", "confidence": "high"})

    assessment = client.get(f"/assessments/{created['id']}").json()
    assert assessment["status"] == "completed"
    assert assessment["completed_at"] is not None


def test_assessment_status_is_partially_completed_with_a_mix_of_recorded_and_failed(client):
    _register_device(client)
    created = client.post(
        "/assessments",
        json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS", "TEST-HTTP-HEADERS"]},
    ).json()
    job_ids = [job["id"] for job in created["jobs"]]

    client.patch(
        f"/scan-jobs/{job_ids[0]}",
        json={"status": "awaiting_finding", "observations": {}, "tool": "curl", "tool_version": "8.5.0", "command": "curl ..."},
    )
    client.post(f"/scan-jobs/{job_ids[0]}/record", json={"finding": "ok", "confidence": "high"})
    client.post(f"/scan-jobs/{job_ids[1]}/record-failure", json={"error_detail": "timed out"})

    assessment = client.get(f"/assessments/{created['id']}").json()
    assert assessment["status"] == "partially_completed"


def test_cancel_assessment_marks_pending_jobs_failed_and_assessment_cancelled(client):
    _register_device(client)
    created = client.post(
        "/assessments", json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS"]},
    ).json()

    response = client.post(f"/assessments/{created['id']}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"

    job = client.get(f"/scan-jobs/{created['jobs'][0]['id']}").json()
    assert job["status"] == "failed"
    assert "cancelled" in job["error"]


def test_cancelled_assessment_stays_cancelled_even_if_a_job_later_completes(client):
    _register_device(client)
    created = client.post(
        "/assessments", json={"device_id": "cam-1", "test_ids": ["TEST-AUTH-DEFAULT-CREDS"]},
    ).json()
    job_id = created["jobs"][0]["id"]

    client.post(f"/assessments/{created['id']}/cancel")
    # Simulate the (already-running) job finishing anyway after cancellation.
    client.patch(f"/scan-jobs/{job_id}", json={"status": "awaiting_finding", "observations": {}})

    assessment = client.get(f"/assessments/{created['id']}").json()
    assert assessment["status"] == "cancelled"


def test_cancel_unknown_assessment_is_404(client):
    assert client.post("/assessments/no-such-id/cancel").status_code == 404
