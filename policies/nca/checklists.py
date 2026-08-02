"""Evaluates a guided checklist's answers into a suggested status - never a
verdict. Mirrors finding_mappings.py's own principle exactly: a suggestion
only ever pre-fills RecordAssessmentDialog, a human still reviews and signs
before anything is recorded (see nca_routes.py's attestation_confirmed
requirement).

Reuses policies/engine/policy_engine.py's existing {field, op, value}
predicate (condition_matches) so there is exactly one evaluation vocabulary
in this codebase for "does this data satisfy this rule" - not a second DSL
invented for checklists on top of the one finding_mappings.py already uses
for scan evidence.

A `suggestion_rule` (stored per-control in compliance_control_checklists) is
an ordered list of:
    {"conditions": [{"field": "answers.<key>", "op": ..., "value": ...}, ...],
     "suggested_status": "pass"|"partial"|"fail"|"review_required"}
evaluated top-to-bottom; a rule matches only when EVERY one of its
conditions matches (AND semantics) against {"answers": {...}} - the first
matching rule wins. Returns None if nothing matches, which every caller
must treat as "no suggestion" - never an implicit pass, matching this
project's "absence of a match is never reported as a pass" rule stated in
finding_mappings.py's own docstring.
"""

from policies.engine.policy_engine import condition_matches


def evaluate_checklist(suggestion_rule: list[dict], answers: dict) -> str | None:
    record = {"answers": answers}
    for rule in suggestion_rule:
        conditions = rule.get("conditions") or []
        if conditions and all(condition_matches(record, condition) for condition in conditions):
            return rule["suggested_status"]
    return None
