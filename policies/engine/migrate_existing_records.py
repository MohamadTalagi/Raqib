import json
import sys
from pathlib import Path

import requests


def migrate_existing_records(evidence_dir: str, verdicts_dir: str, api_url: str) -> tuple[int, int]:
    evidence_count = 0
    for path in sorted(Path(evidence_dir).glob("*.json")):
        record = json.loads(path.read_text())
        response = requests.post(f"{api_url}/evidence", json=record, timeout=10)
        response.raise_for_status()
        evidence_count += 1

    verdict_count = 0
    for path in sorted(Path(verdicts_dir).glob("*.json")):
        record = json.loads(path.read_text())
        response = requests.post(f"{api_url}/verdicts", json=record, timeout=10)
        response.raise_for_status()
        verdict_count += 1

    return evidence_count, verdict_count


def main():
    evidence_count, verdict_count = migrate_existing_records(
        evidence_dir="/work/document-store/evidence",
        verdicts_dir="/work/document-store/verdicts",
        api_url="http://auditor-api:8000",
    )
    print(f"Migrated {evidence_count} evidence records and {verdict_count} verdicts")


if __name__ == "__main__":
    sys.exit(main() or 0)
