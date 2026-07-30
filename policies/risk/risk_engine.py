"""Dynamic Risk Assessment (IoTGuard Stage 06): one pure, centralized,
unit-tested function computes a device's risk score from 7 inputs -
compliance, CVSS, exploit availability, device criticality, internet
exposure, violation count, and insecure-service count - matching this
project's existing pattern for every other scoring engine
(policies/engine/policy_engine.py, policies/nca/evaluator.py): callers only
ever assemble inputs and render this function's output, never recompute a
score themselves.

Deliberately the *opposite* direction from a compliance score: every
normalized factor and the final risk_score are 0-100 where HIGHER = RISKIER.
Never conflate this with device_score()/vuln_routes' compliance
percentages, which run the other way.

Nothing here feeds back into or auto-flips a compliance verdict - matching
this project's "tool-assisted, not tool-decided" rule throughout. This is a
new, independent, informational rollup, never persisted: like device_score()
and vuln_routes._summarize_packages(), it's computed fresh from current data
on every request.
"""

from dataclasses import dataclass

CRITICALITY_LEVELS = ("low", "medium", "high", "critical")
EXPOSURE_LEVELS = ("none", "internal_only", "internet_facing")

_CRITICALITY_RISK = {"low": 25, "medium": 50, "high": 75, "critical": 100}
_EXPOSURE_RISK = {"none": 0, "internal_only": 40, "internet_facing": 100}

# Every point value and cap below is a named, tunable constant - never
# hardcoded inline - matching policies/nca/evaluator.py's
# DEFAULT_PASS_THRESHOLD precedent.
VIOLATION_POINTS_PER_COUNT = 20
INSECURE_SERVICE_POINTS_PER_COUNT = 25

# A device with no compliance assessment at all is not "neutral" - absence
# of proof of compliance is not proof of safety, so this factor scores it as
# maximum risk, same honesty rule policies/nca/evaluator.py's device_score()
# already applies to a never-assessed device (None, never a guessed 0%).
NEVER_ASSESSED_COMPLIANCE_RISK = 100

WEIGHTS = {
    "compliance": 0.25,
    "cvss": 0.20,
    "exploit_availability": 0.20,
    "criticality": 0.15,
    "exposure": 0.10,
    "violations": 0.05,
    "insecure_services": 0.05,
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9, "risk factor weights must sum to 100%"

# Checked highest-first; a score qualifies for the first threshold it meets.
RISK_CATEGORY_THRESHOLDS = (
    ("critical", 75),
    ("high", 50),
    ("medium", 25),
    ("low", 0),
)


@dataclass(frozen=True)
class DeviceRiskInputs:
    """The 7 raw inputs this engine needs for one device, assembled by the
    caller (lab/auditor/api/risk_routes.py) from whatever real source each
    one lives in. Every field is already the raw, real-world value (a
    percentage, a CVSS score, a count) - this dataclass does no
    interpretation of its own, matching vuln_reference.py's precedent for
    typed, frozen dataclasses over plain dicts for structured domain data."""

    compliance_score: int | None  # NCA device_score(): 0-100, or None if never assessed
    highest_cvss: float | None  # highest CVSS across the device's firmware CVEs, or None
    has_kev_listed_cve: bool  # any CISA KEV-listed CVE among the device's findings
    criticality: str  # one of CRITICALITY_LEVELS
    exposure: str  # one of EXPOSURE_LEVELS
    violation_count: int  # SA-IOT FAIL verdicts + NCA fail assessments, combined
    insecure_service_count: int  # enabled http/mqtt/telnet services


def _risk_category(score: int) -> str:
    for category, minimum in RISK_CATEGORY_THRESHOLDS:
        if score >= minimum:
            return category
    return "low"  # unreachable (the "low" entry's minimum is 0), kept for clarity


def compute_device_risk(inputs: DeviceRiskInputs) -> dict:
    """Returns {risk_score, risk_category, breakdown}. `breakdown` carries
    every factor's raw value, normalized 0-100 contribution, weight, and
    weighted contribution - this is what makes the score fully auditable
    rather than a black box; callers render this directly instead of
    re-deriving anything themselves."""
    if inputs.criticality not in CRITICALITY_LEVELS:
        raise ValueError(f"unknown criticality: {inputs.criticality!r}")
    if inputs.exposure not in EXPOSURE_LEVELS:
        raise ValueError(f"unknown exposure: {inputs.exposure!r}")

    compliance_risk = (
        NEVER_ASSESSED_COMPLIANCE_RISK
        if inputs.compliance_score is None
        else 100 - inputs.compliance_score
    )
    cvss_risk = 0.0 if inputs.highest_cvss is None else inputs.highest_cvss * 10
    exploit_risk = 100 if inputs.has_kev_listed_cve else 0
    criticality_risk = _CRITICALITY_RISK[inputs.criticality]
    exposure_risk = _EXPOSURE_RISK[inputs.exposure]
    violation_risk = min(100, inputs.violation_count * VIOLATION_POINTS_PER_COUNT)
    insecure_service_risk = min(
        100, inputs.insecure_service_count * INSECURE_SERVICE_POINTS_PER_COUNT,
    )

    factors = {
        "compliance": (inputs.compliance_score, compliance_risk),
        "cvss": (inputs.highest_cvss, cvss_risk),
        "exploit_availability": (inputs.has_kev_listed_cve, exploit_risk),
        "criticality": (inputs.criticality, criticality_risk),
        "exposure": (inputs.exposure, exposure_risk),
        "violations": (inputs.violation_count, violation_risk),
        "insecure_services": (inputs.insecure_service_count, insecure_service_risk),
    }

    breakdown = {}
    total = 0.0
    for name, (raw, normalized) in factors.items():
        weight = WEIGHTS[name]
        contribution = normalized * weight
        total += contribution
        breakdown[name] = {
            "raw_value": raw,
            "normalized": round(normalized, 1),
            "weight": weight,
            "contribution": round(contribution, 1),
        }

    risk_score = round(total)
    return {
        "risk_score": risk_score,
        "risk_category": _risk_category(risk_score),
        "breakdown": breakdown,
    }
