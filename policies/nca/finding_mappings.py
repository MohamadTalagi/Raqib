"""Maps a piece of automated scan evidence to the NCA controls it's relevant
to - a configurable data table, never a hardcoded if/elif chain in the UI or
API. Reuses policy_engine.py's existing {field, op, value} predicate
(condition_matches) so there is exactly one evidence-matching vocabulary in
this codebase, not a second DSL invented for this module.

A match only ever *suggests* a control link; it never writes a
compliance_assessments row by itself. A human still decides the finding text,
status, and severity for that assessment - same "AI-assisted, not
AI-decided" principle the rest of the project already follows for
evidence/verdicts. Do not infer organizational controls (policy approval,
personnel training, independent audit, supplier-contract compliance) from a
network or device scan - there are deliberately no automated mappings to any
guideline in domain 1, or to the supplier/cloud guideline groups; those stay
manual-assessment-only.
"""

from policies.engine.policy_engine import condition_matches


def _field_present(record: dict, dotted_path: str) -> bool:
    """Whether the dotted path resolves to an actual key, not just a falsy
    value. Without this check, evidence from an unrelated test (which simply
    never populates this observation key at all) would still spuriously
    match a "not_equals" rule - "field absent" and "field is None" both
    compare not-equal to nearly everything (None != [] and None != False are
    both True), so a mapping could fire on evidence it has nothing to do
    with. A mapping should only ever be evaluated against evidence that
    actually carries the observation it's keyed on."""
    value = record
    for part in dotted_path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return False
    return True


def map_evidence_to_mappings(evidence: dict, mappings: list[dict]) -> list[dict]:
    """Returns every enabled mapping whose match_rule matches this evidence
    record - the full mapping dicts, not just their control_ids, so callers
    that need the mapping's description/verdict_hint (e.g. the per-device
    assessment workspace's auto-verdict suggestions) don't re-run the match.
    `evidence` is a full evidence-table row (dotted match_rule fields like
    "observations.default_creds" reach into its JSONB observations column);
    `mappings` is the compliance_finding_mappings table's rows, each already
    carrying its own match_rule dict."""
    return [
        mapping
        for mapping in mappings
        if mapping.get("enabled", True)
        and _field_present(evidence, mapping["match_rule"]["field"])
        and condition_matches(evidence, mapping["match_rule"])
    ]


def map_evidence_to_controls(evidence: dict, mappings: list[dict]) -> list[str]:
    """Returns the control_id of every enabled mapping whose match_rule
    matches this evidence record. Thin wrapper over map_evidence_to_mappings
    so there is exactly one evidence-matching path."""
    return [mapping["control_id"] for mapping in map_evidence_to_mappings(evidence, mappings)]
