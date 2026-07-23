"""Evidence conflict detection - the mentor brief's own example: documentation
claims MQTT uses TLS, a packet capture shows plaintext MQTT. The system must
record both evidence items, prefer directly observed technical evidence over
documentation, mark the conflict, and explain the resulting verdict.

This runs at verdict-recompute time, comparing every evidence row that maps
to the same (device_id, control_id) pair - not inside policy_engine.evaluate()
itself, which stays a single-evidence-record function. The caller picks a
winning evidence row via detect_conflict() and passes it (plus the conflict
flags) into evaluate().
"""

from policies.engine.policy_engine import _get_field

# Evidence with no source_type recorded (pre-dating this field) is treated as
# automated - the overwhelming majority of historical evidence in this project
# came from a scan_tests.py collector, not a manually-entered document.
_DEFAULT_SOURCE_TYPE = "automated"


def _condition_fields(control: dict) -> set[str]:
    conditions = control.get("conditions") or {}
    fields = set()
    for key in ("pass", "fail"):
        condition = conditions.get(key)
        if condition and not condition.get("when"):
            fields.add(condition["field"])
    return fields


def detect_conflict(control: dict, evidence_rows: list[dict]) -> tuple[dict | None, bool, str | None]:
    """Returns (chosen_evidence, conflict_detected, conflict_reason) for one
    (device, control) pair's full set of relevant evidence rows.

    A conflict exists when two rows disagree on the value of a field the
    control's pass/fail conditions actually key on. When one does, the row
    whose source_type == "automated" wins over "manual"/"document" rows;
    ties (or no automated row at all) fall back to the most recent
    timestamp, same as the no-conflict case.
    """
    if not evidence_rows:
        return None, False, None
    if len(evidence_rows) == 1:
        return evidence_rows[0], False, None

    fields = _condition_fields(control)
    conflicting_fields = []
    for field in sorted(fields):
        # A plain set() can't hold unhashable observation values (e.g.
        # observations.open_ports is a list) - compare by equality instead.
        values = [_get_field(row, field) for row in evidence_rows]
        values = [v for v in values if v is not None]
        if any(v != values[0] for v in values[1:]):
            conflicting_fields.append(field)

    if not conflicting_fields:
        return max(evidence_rows, key=lambda r: r["timestamp"]), False, None

    automated_rows = [r for r in evidence_rows if r.get("source_type", _DEFAULT_SOURCE_TYPE) == "automated"]
    candidates = automated_rows or evidence_rows
    chosen = max(candidates, key=lambda r: r["timestamp"])

    reason = (
        f"Conflicting evidence on {', '.join(conflicting_fields)}: "
        f"{chosen['evidence_id']} (source_type={chosen.get('source_type', _DEFAULT_SOURCE_TYPE)}) "
        f"was preferred over {len(evidence_rows) - 1} other disagreeing record(s) "
        f"({', '.join(r['evidence_id'] for r in evidence_rows if r is not chosen)})."
    )
    return chosen, True, reason
