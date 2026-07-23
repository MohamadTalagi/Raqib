"""The single centralized evaluator for NCA CGIoT-1:2024 compliance status.

Every status/score/domain-count the dashboard shows comes from these pure
functions - the frontend only ever renders numbers and strings this module
already computed (see docs/nca-compliance.md's "status-calculation rules"
section). Do not duplicate this logic in API route handlers or in the UI.

Input rows are plain dicts, one per (control, device-or-org-scope) pair,
already reduced to the LATEST non-superseded assessment (superseded_by IS
NULL) - see nca_routes.py's query layer for how rows are assembled:

    {
        "control_id": str,
        "domain_id": str,               # "1".."4"
        "required": bool,
        "status": "pass"|"partial"|"fail"|"not_tested",
        "applicability": "applicable"|"not_applicable",
        "evidence_expired": bool,       # linked evidence's retention_expires_at is in the past
        "exception_active": bool,       # an APPROVED, unexpired exception exists for this (control, scope)
    }
"""

from typing import Literal

Status = Literal["pass", "partial", "fail", "not_tested"]
DeviceOverallStatus = Literal["pass", "partial", "fail", "not_tested"]

STATUSES: tuple[Status, ...] = ("pass", "partial", "fail", "not_tested")

# The 4 UI-facing domain groups the brief names, keyed by the standard's own
# top-level domain_id.
DOMAIN_GROUPS: dict[str, str] = {
    "1": "Cybersecurity Governance",
    "2": "Cybersecurity Defense",
    "3": "Cybersecurity Resilience",
    "4": "Third-Party and Cloud Computing Cybersecurity",
}


def effective_status(row: dict) -> Status:
    """The status used for aggregation - never mutates the stored assessment
    row. Only a PASS can be rolled down by expired evidence (per the brief:
    "Roll expired required evidence into PARTIAL status"); a FAIL, PARTIAL,
    or NOT_TESTED result stays exactly what it already is regardless of
    evidence freshness - expiry never turns a FAIL into something else, and
    it never *improves* a status either."""
    status = row["status"]
    if status == "pass" and row.get("evidence_expired"):
        return "partial"
    return status


def is_effectively_applicable(row: dict) -> bool:
    """An approved, unexpired exception has the same aggregation effect as
    applicability=not_applicable - the control is excluded from the
    denominator either way, even though they're recorded as different things
    (an exception is a risk-accepted deviation with a compensating control,
    not a claim the control doesn't apply). Both still require a written
    rationale/approver at the point they're created - that's enforced by the
    API layer, not here."""
    if row["applicability"] == "not_applicable":
        return False
    if row.get("exception_active"):
        return False
    return True


def _applicable_required(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["required"] and is_effectively_applicable(r)]


def device_overall_status(rows: list[dict]) -> DeviceOverallStatus:
    """Exact precedence from the brief:
      - FAIL if any applicable required control has status FAIL.
      - PARTIAL if there are no failures but at least one required control is
        PARTIAL, NOT_TESTED, missing evidence, or expired evidence.
      - PASS only when every applicable required control is PASS with
        current evidence.
      - Excludes approved not-applicable (and excepted) controls from the
        denominator entirely.

    One case the brief's own 3-outcome wording doesn't disambiguate: a device
    with ZERO applicable+required assessments at all (nothing has ever been
    tested) would otherwise satisfy "at least one required control is
    NOT_TESTED" vacuously. The caller (nca_routes._evaluator_rows_for_scope)
    always supplies one row per enabled control, defaulting an untouched
    control's status to "not_tested" rather than omitting it - so an
    entirely-untouched device's rows are never an empty list, they're a full
    list where every status is "not_tested". Both shapes are treated as
    "not_tested" (the UI's "Not Assessed" bucket) rather than PARTIAL, since
    "partially compliant" implies some assessment work has actually
    happened; a device with at least one real result mixed with some
    not-yet-tested controls still correctly rolls into PARTIAL below.
    """
    applicable_required = _applicable_required(rows)
    if not applicable_required:
        return "not_tested"

    statuses = [effective_status(r) for r in applicable_required]
    if all(s == "not_tested" for s in statuses):
        return "not_tested"
    if any(s == "fail" for s in statuses):
        return "fail"
    if any(s in ("partial", "not_tested") for s in statuses):
        return "partial"
    return "pass"


def device_score(rows: list[dict]) -> int | None:
    """passed / total over applicable+required controls only, rounded.
    `None` when the denominator is 0, or when every applicable+required
    control is still "not_tested" - the same "nothing has ever been
    assessed" case device_overall_status treats as its own outcome rather
    than as 0%, since a fresh, unassessed device reading "0%" would look
    like a fleet of failures rather than pending work. Purely informational:
    this function's return value is never fed back into
    device_overall_status, and callers must not use it to override the
    strict status computed above."""
    applicable_required = _applicable_required(rows)
    if not applicable_required:
        return None
    statuses = [effective_status(r) for r in applicable_required]
    if all(s == "not_tested" for s in statuses):
        return None
    passed = sum(1 for s in statuses if s == "pass")
    return round(passed / len(applicable_required) * 100)


def domain_summary(rows: list[dict]) -> dict[str, dict[str, int]]:
    """PASS/PARTIAL/FAIL/NOT_TESTED counts per the 4 UI-facing domain groups,
    across every effectively-applicable control (required and optional
    alike - this is a coverage view, not the strict required-only score)."""
    buckets: dict[str, dict[str, int]] = {
        name: {status: 0 for status in STATUSES} for name in DOMAIN_GROUPS.values()
    }
    for row in rows:
        if not is_effectively_applicable(row):
            continue
        domain_name = DOMAIN_GROUPS.get(row["domain_id"], row["domain_id"])
        buckets.setdefault(domain_name, {status: 0 for status in STATUSES})
        buckets[domain_name][effective_status(row)] += 1
    return buckets
