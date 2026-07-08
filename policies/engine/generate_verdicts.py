import sys
from pathlib import Path

import requests
import yaml

from policies.engine.policy_engine import evaluate


def generate_verdicts(api_url: str, controls_dir: str) -> list[dict]:
    evidence_response = requests.get(f"{api_url}/evidence", timeout=10)
    evidence_response.raise_for_status()
    evidence_records = sorted(evidence_response.json(), key=lambda e: e["evidence_id"])

    controls = []
    for path in sorted(Path(controls_dir).glob("*.yaml")):
        controls.append(yaml.safe_load(path.read_text()))

    verdicts = []
    seq_by_date: dict[str, int] = {}
    for evidence in evidence_records:
        for control in controls:
            required_test_ids = {req["test_id"] for req in control["required_evidence"]}
            if evidence["test_id"] not in required_test_ids:
                continue
            date_str = evidence["timestamp"][:10]
            seq_by_date[date_str] = seq_by_date.get(date_str, 0) + 1
            verdict_id = f"VD-{date_str}-{seq_by_date[date_str]:04d}"
            verdict = evaluate(control, evidence, verdict_id=verdict_id)
            post_response = requests.post(f"{api_url}/verdicts", json=verdict, timeout=10)
            post_response.raise_for_status()
            verdicts.append(verdict)
    return verdicts


def main():
    api_url = "http://auditor-api:8000"
    controls_dir = "/work/policies/controls"
    verdicts = generate_verdicts(api_url=api_url, controls_dir=controls_dir)
    print(f"Generated {len(verdicts)} verdicts")
    for v in verdicts:
        print(f"  {v['control_id']} / {v['device_id']} -> {v['status']}")


if __name__ == "__main__":
    sys.exit(main() or 0)
