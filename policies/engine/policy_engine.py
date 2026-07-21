import json
import operator
from typing import Any, Optional

import yaml

OPS = {
    "equals": operator.eq,
    "not_equals": operator.ne,
    "in": lambda a, b: a in b if b is not None else False,
    "not_in": lambda a, b: a not in b if b is not None else True,
    "greater_than": lambda a, b: a is not None and a > b,
    "less_than": lambda a, b: a is not None and a < b,
    "contains": lambda a, b: b in a if a is not None else False,
    "not_contains": lambda a, b: b not in a if a is not None else True,
}

STATUS_MAP = {"fail": "FAIL", "partial": "PARTIAL", "pass": "PASS", "inconclusive": "INCONCLUSIVE"}


def _get_field(record: dict, dotted_path: str) -> Any:
    value: Any = record
    for part in dotted_path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


def _condition_matches(evidence: dict, condition: Optional[dict]) -> bool:
    if not condition or "when" in condition:
        return False
    field = condition["field"]
    op = condition["op"]
    expected = condition["value"]
    actual = _get_field(evidence, field)
    return OPS[op](actual, expected)


def load_control(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_evidence(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate(control: dict, evidence: dict, verdict_id: Optional[str] = None) -> dict:
    conditions = control["conditions"]
    matched = "inconclusive"
    reason = "no condition matched; evidence insufficient"

    for status in ("fail", "partial", "pass"):
        condition = conditions.get(status)
        if _condition_matches(evidence, condition):
            matched = status
            reason = f"{condition['field']} {condition['op']} {condition['value']}"
            break

    saudi = control["saudi_source"][0]
    result = {
        "control_id": control["control_id"],
        "device_id": evidence["device_id"],
        "status": STATUS_MAP[matched],
        "severity": control["severity"],
        "evidence_ids": [evidence["evidence_id"]],
        "matched": matched,
        "reason": reason,
        "saudi_source": f"{saudi['framework']} §{saudi['reference']}",
        "remediation": control["remediation"],
        "timestamp": evidence["timestamp"],
    }
    if verdict_id:
        result = {"verdict_id": verdict_id, **result}
    return result
