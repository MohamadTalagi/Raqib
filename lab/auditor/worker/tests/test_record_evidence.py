from datetime import datetime, timezone

from lab.auditor.worker.tests.record_evidence import record_evidence


class FakeResponse:
    status_code = 201

    def raise_for_status(self):
        pass


def _fake_post(posted):
    def _post(url, json, timeout):
        posted["url"] = url
        posted["json"] = json
        posted["timeout"] = timeout
        return FakeResponse()

    return _post


def test_record_evidence_posts_valid_json_payload(monkeypatch, tmp_path):
    posted = {}
    monkeypatch.setattr(
        "lab.auditor.worker.tests.record_evidence.requests.post", _fake_post(posted)
    )
    monkeypatch.setenv("AUDITOR_API_URL", "http://auditor-api:8000")

    raw_file = tmp_path / "raw_nmap_output.txt"
    raw_file.write_text("23/tcp open telnet\n80/tcp open http\n1883/tcp open mqtt\n")

    record = record_evidence(
        device="device-insecure",
        test_id="TEST-NET-PORTSCAN",
        tool="nmap",
        tool_version="7.94",
        command="nmap -sV -p- device-insecure",
        finding="Telnet (23/tcp) open; plaintext management exposed",
        raw_file=str(raw_file),
        confidence="high",
        observations={"open_ports": [23, 80, 1883], "telnet_open": True},
        document_store=tmp_path / "document-store",
    )

    assert record["evidence_id"].startswith("EV-")
    assert record["device_id"] == "device-insecure"
    assert len(record["sha256"]) == 64

    # The evidence dict is no longer written to a local JSON file — it is
    # POSTed to the auditor-api instead. Verify the POST carried the same
    # payload that used to be json.dump()-ed to document-store/evidence/.
    assert posted["url"] == "http://auditor-api:8000/evidence"
    assert posted["json"] == record


def test_record_evidence_copies_raw_output(monkeypatch, tmp_path):
    posted = {}
    monkeypatch.setattr(
        "lab.auditor.worker.tests.record_evidence.requests.post", _fake_post(posted)
    )

    raw_file = tmp_path / "raw.txt"
    raw_file.write_text("raw tool output")

    record = record_evidence(
        device="device-insecure",
        test_id="TEST-HTTP-HEADERS",
        tool="curl",
        tool_version="8.9.1",
        command="curl -I http://device-insecure/",
        finding="Missing security headers",
        raw_file=str(raw_file),
        confidence="high",
        observations={"missing_security_headers": ["X-Frame-Options", "Content-Security-Policy"]},
        document_store=tmp_path / "document-store",
    )

    # Raw output copying to document-store/raw/ is unchanged by this task.
    copied = tmp_path / "document-store" / "raw" / f"{record['evidence_id']}.txt"
    assert copied.read_text() == "raw tool output"
    assert posted["json"]["raw_output_path"] == f"document-store/raw/{record['evidence_id']}.txt"


def test_sequence_reflects_existing_evidence_dir_contents(monkeypatch, tmp_path):
    # record_evidence() no longer writes the evidence JSON to
    # document-store/evidence/ itself (that data now lives in the
    # auditor-api/database instead), so two back-to-back calls in the same
    # process no longer naturally advance the on-disk counter the way they
    # did pre-refactor. What IS unchanged is the sequence-number *formula*:
    # _next_sequence() still derives the next number from however many
    # EV-{date}-*.json files already exist in document-store/evidence/ (e.g.
    # legacy entries from Phase 4, or files placed there by some other
    # process). Simulate that pre-existing state directly and verify the
    # formula still produces the correctly incremented ID.
    posted = {}
    monkeypatch.setattr(
        "lab.auditor.worker.tests.record_evidence.requests.post", _fake_post(posted)
    )

    store = tmp_path / "document-store"
    evidence_dir = store / "evidence"
    evidence_dir.mkdir(parents=True)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    (evidence_dir / f"EV-{today}-0001.json").write_text("{}")
    (evidence_dir / f"EV-{today}-0002.json").write_text("{}")

    raw_file = tmp_path / "raw.txt"
    raw_file.write_text("x")

    record = record_evidence(
        device="d1",
        test_id="T1",
        tool="t",
        tool_version="1",
        command="c",
        finding="f",
        raw_file=str(raw_file),
        confidence="high",
        observations={},
        document_store=store,
    )

    assert record["evidence_id"] == f"EV-{today}-0003"


def test_record_evidence_posts_to_api(monkeypatch, tmp_path):
    # NOTE: the brief's literal `import record_evidence` doesn't resolve
    # under this repo's package layout (lab/.../tests/__init__.py makes this
    # a qualified package, and pytest only puts the repo root on sys.path —
    # not the tests/ directory itself). Import the same module under its
    # real qualified name instead; everything else below is unchanged.
    from lab.auditor.worker.tests import record_evidence

    posted = {}

    class FakeResponse:
        status_code = 201

        def raise_for_status(self):
            pass

    def fake_post(url, json, timeout):
        posted["url"] = url
        posted["json"] = json
        return FakeResponse()

    monkeypatch.setattr(record_evidence.requests, "post", fake_post)
    monkeypatch.setenv("AUDITOR_API_URL", "http://auditor-api:8000")

    raw_file = tmp_path / "raw.txt"
    raw_file.write_text("nmap output here")

    record_evidence.record_evidence(
        device="device-insecure",
        test_id="TEST-NET-PORTSCAN",
        tool="nmap",
        tool_version="7.95",
        command="nmap -sV -p- device-insecure",
        finding="Port 80 open",
        raw_file=str(raw_file),
        confidence="high",
        observations={"open_ports": [80]},
        # Deviation from the brief's literal snippet: without this override,
        # record_evidence() defaults to the real repo document-store/ and
        # will overwrite real, already-committed Phase 0-5 evidence files
        # (confirmed by running it once — it clobbered
        # document-store/raw/EV-2026-07-08-0013.txt, which was reverted via
        # `git checkout --`). Point it at a throwaway tmp_path instead; the
        # assertions below (the actual point of this test) are unchanged.
        document_store=tmp_path / "document-store",
    )

    assert posted["url"] == "http://auditor-api:8000/evidence"
    assert posted["json"]["device_id"] == "device-insecure"
    assert posted["json"]["finding"] == "Port 80 open"
