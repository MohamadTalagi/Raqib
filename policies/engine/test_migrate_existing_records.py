import json

import responses

from policies.engine.migrate_existing_records import migrate_existing_records


@responses.activate
def test_migrate_existing_records_posts_every_file(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    verdicts_dir = tmp_path / "verdicts"
    verdicts_dir.mkdir()

    evidence = {"evidence_id": "EV-2026-07-08-0013", "device_id": "device-insecure"}
    (evidence_dir / "EV-2026-07-08-0013.json").write_text(json.dumps(evidence))

    verdict = {"verdict_id": "VD-2026-07-08-0001", "control_id": "SA-IOT-003"}
    (verdicts_dir / "VD-2026-07-08-0001.json").write_text(json.dumps(verdict))

    api_url = "http://auditor-api:8000"
    responses.add(responses.POST, f"{api_url}/evidence", json=evidence, status=201)
    responses.add(responses.POST, f"{api_url}/verdicts", json=verdict, status=201)

    evidence_count, verdict_count = migrate_existing_records(
        evidence_dir=str(evidence_dir), verdicts_dir=str(verdicts_dir), api_url=api_url,
    )

    assert evidence_count == 1
    assert verdict_count == 1
    post_bodies = [json.loads(c.request.body) for c in responses.calls]
    assert evidence in post_bodies
    assert verdict in post_bodies
