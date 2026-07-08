import json
from pathlib import Path

from lab.auditor.worker.tests.record_evidence import record_evidence


def test_record_evidence_writes_valid_json(tmp_path):
    raw_file = tmp_path / "raw_nmap_output.txt"
    raw_file.write_text("23/tcp open telnet\n80/tcp open http\n1883/tcp open mqtt\n")

    record = record_evidence(
        device_id="device-insecure",
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

    out_file = tmp_path / "document-store" / "evidence" / f"{record['evidence_id']}.json"
    assert out_file.exists()
    saved = json.loads(out_file.read_text())
    assert saved == record


def test_record_evidence_copies_raw_output(tmp_path):
    raw_file = tmp_path / "raw.txt"
    raw_file.write_text("raw tool output")

    record = record_evidence(
        device_id="device-insecure",
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

    copied = tmp_path / "document-store" / "raw" / f"{record['evidence_id']}.txt"
    assert copied.read_text() == "raw tool output"


def test_sequence_increments_within_same_day(tmp_path):
    raw_file = tmp_path / "raw.txt"
    raw_file.write_text("x")
    store = tmp_path / "document-store"

    first = record_evidence(
        device_id="d1", test_id="T1", tool="t", tool_version="1", command="c",
        finding="f", raw_file=str(raw_file), confidence="high", observations={},
        document_store=store,
    )
    second = record_evidence(
        device_id="d1", test_id="T2", tool="t", tool_version="1", command="c",
        finding="f", raw_file=str(raw_file), confidence="high", observations={},
        document_store=store,
    )
    assert first["evidence_id"] != second["evidence_id"]
