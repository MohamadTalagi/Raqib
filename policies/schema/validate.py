import json
from pathlib import Path
from jsonschema import validate

SCHEMA_DIR = Path(__file__).parent


def _load_schema(name: str) -> dict:
    with open(SCHEMA_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


EVIDENCE_SCHEMA = _load_schema("evidence.schema.json")
VERDICT_SCHEMA = _load_schema("verdict.schema.json")
CONTROL_SCHEMA = _load_schema("control.schema.json")


def validate_evidence(record: dict) -> None:
    validate(instance=record, schema=EVIDENCE_SCHEMA)


def validate_verdict(record: dict) -> None:
    validate(instance=record, schema=VERDICT_SCHEMA)


def validate_control(record: dict) -> None:
    validate(instance=record, schema=CONTROL_SCHEMA)
