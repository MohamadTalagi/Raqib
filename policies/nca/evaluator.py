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
        "status": "pass"|"partial"|"fail"|"not_tested"|"review_required",
        "applicability": "applicable"|"not_applicable",
        "evidence_expired": bool,       # linked evidence's retention_expires_at is in the past
        "exception_active": bool,       # an APPROVED, unexpired exception exists for this (control, scope)
        "severity": "low"|"medium"|"high"|"critical",  # the CONTROL's severity, only used by overall_classification
        "blocking": bool,               # the CONTROL's blocking flag, only used by overall_classification/has_blocking_failure
    }

REVIEW_REQUIRED is distinct from NOT_TESTED: it means an assessment WAS
recorded but something about it (most commonly conflicting evidence, per
policies/engine/conflict.py's SA-IOT-* precedent) means it needs a human to
look at it again before it can count as a real pass or fail. It rolls up
into device_overall_status's existing PARTIAL bucket (a device with a
review-required control isn't "not yet assessed", it has a real, if
unresolved, result) but is tracked separately by overall_classification
below, since the brief requires it to visibly block a "Passed" verdict on
its own, distinct from a plain NOT_TESTED gap.
"""

from typing import Literal, TypedDict

Status = Literal["pass", "partial", "fail", "not_tested", "review_required"]
DeviceOverallStatus = Literal["pass", "partial", "fail", "not_tested"]
Classification = Literal["passed", "partially_passed", "failed"]

STATUSES: tuple[Status, ...] = ("pass", "partial", "fail", "not_tested", "review_required")

DEFAULT_PASS_THRESHOLD = 85
DEFAULT_PARTIAL_THRESHOLD = 50


class OverallClassification(TypedDict):
    classification: Classification
    score: int | None
    reasons: list[str]
    blocking_control_ids: list[str]
    critical_failure_control_ids: list[str]
    not_tested_control_ids: list[str]
    review_required_control_ids: list[str]
    pass_threshold: int
    partial_threshold: int

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
    if any(s in ("partial", "not_tested", "review_required") for s in statuses):
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


def has_blocking_failure(rows: list[dict]) -> list[dict]:
    """Applicable+required rows whose current effective status is FAIL and
    whose control is flagged `blocking=True` (see build_catalog.py's
    BLOCKING_GUIDELINES: default/hard-coded credentials, unencrypted
    sensitive data, unnecessary/insecure exposed services) - severe enough
    that a good score elsewhere must not offset them. Returns the offending
    rows (empty list = no blocking failure) rather than a bare bool so a
    caller can report *which* control(s) triggered it."""
    return [
        r for r in _applicable_required(rows)
        if r.get("blocking") and effective_status(r) == "fail"
    ]


def overall_classification(
    rows: list[dict],
    *,
    pass_threshold: int = DEFAULT_PASS_THRESHOLD,
    partial_threshold: int = DEFAULT_PARTIAL_THRESHOLD,
) -> OverallClassification:
    """The Passed / Partially Passed / Failed compliance-readiness
    classification: additive alongside (never replacing) device_overall_status
    and device_score above, which the existing dashboard keeps using
    unchanged. Exact rules, thresholds configurable:

      - Failed: a blocking-flagged control failed, OR no applicable required
        control has ever produced a pass/partial/fail/review_required result,
        OR score < partial_threshold (50%).
      - Partially Passed: score >= partial_threshold but < pass_threshold
        (50-84.99%); OR score >= pass_threshold but a critical-severity
        control failed; OR a mandatory control is still NOT_TESTED; OR a
        mandatory control is REVIEW_REQUIRED.
      - Passed: score >= pass_threshold (85%), no critical-severity failure,
        no blocking condition, no mandatory control NOT_TESTED or
        REVIEW_REQUIRED.

    Deliberately does not rely on the percentage alone - a blocking condition
    or a critical failure overrides a high score, per the brief's own
    "Do not rely only on the percentage" requirement.
    """
    applicable_required = _applicable_required(rows)
    blocking_rows = has_blocking_failure(rows)

    if not applicable_required:
        return {
            "classification": "failed",
            "score": None,
            "reasons": [
                "No applicable required controls exist for this scope - "
                "readiness cannot be demonstrated without at least one assessed control."
            ],
            "blocking_control_ids": [],
            "critical_failure_control_ids": [],
            "not_tested_control_ids": [],
            "review_required_control_ids": [],
            "pass_threshold": pass_threshold,
            "partial_threshold": partial_threshold,
        }

    score = device_score(rows)
    critical_failure_rows = [
        r for r in applicable_required
        if effective_status(r) == "fail" and r.get("severity") == "critical"
    ]
    not_tested_rows = [r for r in applicable_required if effective_status(r) == "not_tested"]
    review_required_rows = [r for r in applicable_required if effective_status(r) == "review_required"]

    reasons: list[str] = []
    if blocking_rows:
        classification: Classification = "failed"
        reasons.append(
            f"{len(blocking_rows)} control(s) flagged as a blocking risk failed: "
            + ", ".join(r["control_id"] for r in blocking_rows)
        )
    elif score is None:
        classification = "failed"
        reasons.append("No applicable required control has produced a pass/partial/fail result yet.")
    elif score < partial_threshold:
        classification = "failed"
        reasons.append(f"Score {score}% is below the failing threshold of {partial_threshold}%.")
    elif critical_failure_rows:
        classification = "partially_passed"
        reasons.append(
            f"{len(critical_failure_rows)} critical-severity control(s) failed: "
            + ", ".join(r["control_id"] for r in critical_failure_rows)
        )
    elif not_tested_rows:
        classification = "partially_passed"
        reasons.append(f"{len(not_tested_rows)} mandatory control(s) have not been tested.")
    elif review_required_rows:
        classification = "partially_passed"
        reasons.append(f"{len(review_required_rows)} mandatory control(s) require review.")
    elif score < pass_threshold:
        classification = "partially_passed"
        reasons.append(f"Score {score}% is below the passing threshold of {pass_threshold}%.")
    else:
        classification = "passed"
        reasons.append(
            f"Score {score}% meets the passing threshold with no critical failures, "
            "blocking conditions, or outstanding mandatory items."
        )

    return {
        "classification": classification,
        "score": score,
        "reasons": reasons,
        "blocking_control_ids": [r["control_id"] for r in blocking_rows],
        "critical_failure_control_ids": [r["control_id"] for r in critical_failure_rows],
        "not_tested_control_ids": [r["control_id"] for r in not_tested_rows],
        "review_required_control_ids": [r["control_id"] for r in review_required_rows],
        "pass_threshold": pass_threshold,
        "partial_threshold": partial_threshold,
    }
