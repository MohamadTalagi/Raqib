import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from policies.schema.validate import validate_evidence

DOCUMENT_STORE = Path(__file__).resolve().parents[3] / "document-store"


def _next_sequence(evidence_dir: Path, date_str: str) -> int:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    existing = list(evidence_dir.glob(f"EV-{date_str}-*.json"))
    return len(existing) + 1


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def record_evidence(
    device_id: str,
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
    evidence_dir = document_store / "evidence"
    raw_dir = document_store / "raw"

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    seq = _next_sequence(evidence_dir, date_str)
    evidence_id = f"EV-{date_str}-{seq:04d}"

    raw_path = Path(raw_file)
    sha256 = _sha256_file(raw_path)

    raw_dir.mkdir(parents=True, exist_ok=True)
    stored_raw_path = raw_dir / f"{evidence_id}.txt"
    stored_raw_path.write_bytes(raw_path.read_bytes())

    record = {
        "evidence_id": evidence_id,
        "device_id": device_id,
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

    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_path = evidence_dir / f"{evidence_id}.json"
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
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
        device_id=args.device,
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
