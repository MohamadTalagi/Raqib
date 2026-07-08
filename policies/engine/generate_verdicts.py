import json
from pathlib import Path
from typing import List

from policies.engine.policy_engine import evaluate, load_control, load_evidence
from policies.schema.validate import validate_verdict


def generate_verdicts(evidence_dir: Path, controls_dir: Path, output_dir: Path) -> List[dict]:
    output_dir.mkdir(parents=True, exist_ok=True)

    controls = [load_control(str(p)) for p in sorted(Path(controls_dir).glob("SA-IOT-*.yaml"))]
    evidence_records = [load_evidence(str(p)) for p in sorted(Path(evidence_dir).glob("*.json"))]

    verdicts = []
    seq = 0
    for evidence in evidence_records:
        for control in controls:
            required_test_ids = {req["test_id"] for req in control["required_evidence"]}
            if evidence["test_id"] not in required_test_ids:
                continue
            seq += 1
            date_str = evidence["timestamp"][:10]
            verdict_id = f"VD-{date_str}-{seq:04d}"
            verdict = evaluate(control, evidence, verdict_id=verdict_id)
            validate_verdict(verdict)
            out_path = Path(output_dir) / f"{verdict_id}.json"
            out_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
            verdicts.append(verdict)

    return verdicts


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    verdicts = generate_verdicts(
        evidence_dir=repo_root / "document-store" / "evidence",
        controls_dir=repo_root / "policies" / "controls",
        output_dir=repo_root / "document-store" / "verdicts",
    )
    for v in verdicts:
        print(f"{v['verdict_id']}: {v['control_id']} / {v['device_id']} -> {v['status']}")


if __name__ == "__main__":
    main()
