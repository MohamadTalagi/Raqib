import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

from policies.schema.validate import validate_evidence

DOCUMENT_STORE = Path(__file__).resolve().parents[4] / "document-store"


def _next_sequence(api_url: str, date_str: str) -> int:
    response = requests.get(f"{api_url}/evidence", timeout=10)
    response.raise_for_status()
    prefix = f"EV-{date_str}-"
    existing = [e for e in response.json() if e["evidence_id"].startswith(prefix)]
    return len(existing) + 1


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def record_evidence(
    device: str,
    test_id: str,
    tool: str,
    tool_version: str,
    command: str,
    finding: str,
    raw_file: str,
    confidence: str,
    observations: dict,
    document_store: Path = DOCUMENT_STORE,
) -> dict:
    raw_dir = document_store / "raw"

    api_url = os.environ.get("AUDITOR_API_URL", "http://auditor-api:8000")

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    seq = _next_sequence(api_url, date_str)
    evidence_id = f"EV-{date_str}-{seq:04d}"

    raw_path = Path(raw_file)
    sha256 = _sha256_file(raw_path)

    raw_dir.mkdir(parents=True, exist_ok=True)
    stored_raw_path = raw_dir / f"{evidence_id}.txt"
    stored_raw_path.write_bytes(raw_path.read_bytes())

    record = {
        "evidence_id": evidence_id,
        "device_id": device,
        "test_id": test_id,
        "tool": tool,
        "tool_version": tool_version,
        "command": command,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finding": finding,
        "observations": observations,
        "raw_output_path": f"document-store/raw/{evidence_id}.txt",
        "confidence": confidence,
        "sha256": sha256,
    }
    validate_evidence(record)

    response = requests.post(f"{api_url}/evidence", json=record, timeout=10)
    response.raise_for_status()

    return record


def main() -> None:
    parser = argparse.ArgumentParser(description="Record a manual evidence entry")
    parser.add_argument("--device", required=True)
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--finding", required=True)
    parser.add_argument("--raw-file", required=True)
    parser.add_argument("--confidence", required=True, choices=["high", "medium", "low"])
    parser.add_argument("--observations", required=True, help="JSON string")
    args = parser.parse_args()

    record = record_evidence(
        device=args.device,
        test_id=args.test_id,
        tool=args.tool,
        tool_version=args.tool_version,
        command=args.command,
        finding=args.finding,
        raw_file=args.raw_file,
        confidence=args.confidence,
        observations=json.loads(args.observations),
    )
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
