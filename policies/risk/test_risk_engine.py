import pytest

from policies.risk.risk_engine import (
    CRITICALITY_LEVELS,
    EXPOSURE_LEVELS,
    NEVER_ASSESSED_COMPLIANCE_RISK,
    RISK_CATEGORY_THRESHOLDS,
    WEIGHTS,
    DeviceRiskInputs,
    _risk_category,
    compute_device_risk,
)

CLEAN_INPUTS = DeviceRiskInputs(
    compliance_score=100,
    highest_cvss=None,
    has_kev_listed_cve=False,
    criticality="low",
    exposure="none",
    violation_count=0,
    insecure_service_count=0,
)

WORST_INPUTS = DeviceRiskInputs(
    compliance_score=None,
    highest_cvss=10.0,
    has_kev_listed_cve=True,
    criticality="critical",
    exposure="internet_facing",
    violation_count=10,
    insecure_service_count=10,
)


def test_weights_sum_to_100_percent():
    assert sum(WEIGHTS.values()) == pytest.approx(1.0)


def test_a_fully_clean_device_scores_low_risk():
    result = compute_device_risk(CLEAN_INPUTS)
    assert result["risk_score"] < 25
    assert result["risk_category"] == "low"


def test_the_worst_possible_device_scores_100_critical():
    result = compute_device_risk(WORST_INPUTS)
    assert result["risk_score"] == 100
    assert result["risk_category"] == "critical"


# -- compliance factor --------------------------------------------------


def test_compliance_risk_is_the_inverse_of_the_compliance_percentage():
    result = compute_device_risk(
        DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "compliance_score": 70}),
    )
    assert result["breakdown"]["compliance"]["normalized"] == 30


def test_never_assessed_compliance_is_treated_as_maximum_risk_not_neutral():
    # Absence of proof of compliance is not proof of safety - a device that
    # was never assessed must not score as if it were perfectly compliant.
    result = compute_device_risk(
        DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "compliance_score": None}),
    )
    assert result["breakdown"]["compliance"]["normalized"] == NEVER_ASSESSED_COMPLIANCE_RISK
    assert result["breakdown"]["compliance"]["raw_value"] is None


# -- CVSS factor ----------------------------------------------------------


def test_cvss_risk_scales_the_0_to_10_score_to_0_to_100():
    result = compute_device_risk(
        DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "highest_cvss": 7.5}),
    )
    assert result["breakdown"]["cvss"]["normalized"] == 75


def test_no_cvss_data_contributes_zero_risk_from_this_factor():
    result = compute_device_risk(CLEAN_INPUTS)  # highest_cvss=None
    assert result["breakdown"]["cvss"]["normalized"] == 0


# -- exploit availability (CISA KEV) factor --------------------------------


def test_a_kev_listed_cve_maxes_out_the_exploit_availability_factor():
    result = compute_device_risk(
        DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "has_kev_listed_cve": True}),
    )
    assert result["breakdown"]["exploit_availability"]["normalized"] == 100


def test_no_kev_listed_cve_contributes_zero_risk_from_this_factor():
    result = compute_device_risk(CLEAN_INPUTS)
    assert result["breakdown"]["exploit_availability"]["normalized"] == 0


# -- device criticality factor ---------------------------------------------


@pytest.mark.parametrize(
    "criticality,expected", [("low", 25), ("medium", 50), ("high", 75), ("critical", 100)],
)
def test_criticality_maps_to_its_documented_risk_value(criticality, expected):
    result = compute_device_risk(
        DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "criticality": criticality}),
    )
    assert result["breakdown"]["criticality"]["normalized"] == expected


def test_rejects_an_unknown_criticality_value():
    with pytest.raises(ValueError, match="criticality"):
        compute_device_risk(
            DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "criticality": "extreme"}),
        )


# -- internet exposure factor -----------------------------------------------


@pytest.mark.parametrize(
    "exposure,expected", [("none", 0), ("internal_only", 40), ("internet_facing", 100)],
)
def test_exposure_maps_to_its_documented_risk_value(exposure, expected):
    result = compute_device_risk(
        DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "exposure": exposure}),
    )
    assert result["breakdown"]["exposure"]["normalized"] == expected


def test_rejects_an_unknown_exposure_value():
    with pytest.raises(ValueError, match="exposure"):
        compute_device_risk(
            DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "exposure": "outer-space"}),
        )


# -- violation count factor (capped) -----------------------------------------


@pytest.mark.parametrize("count,expected", [(0, 0), (1, 20), (3, 60), (5, 100), (10, 100)])
def test_violation_count_scales_then_caps_at_100(count, expected):
    result = compute_device_risk(
        DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "violation_count": count}),
    )
    assert result["breakdown"]["violations"]["normalized"] == expected


# -- insecure-service count factor (capped) ----------------------------------


@pytest.mark.parametrize("count,expected", [(0, 0), (1, 25), (3, 75), (4, 100), (8, 100)])
def test_insecure_service_count_scales_then_caps_at_100(count, expected):
    result = compute_device_risk(
        DeviceRiskInputs(**{**vars(CLEAN_INPUTS), "insecure_service_count": count}),
    )
    assert result["breakdown"]["insecure_services"]["normalized"] == expected


# -- category thresholds (both boundaries of every category) ----------------


@pytest.mark.parametrize(
    "score,expected_category",
    [(0, "low"), (24, "low"), (25, "medium"), (49, "medium"), (50, "high"), (74, "high"), (75, "critical"), (100, "critical")],
)
def test_risk_category_thresholds_at_every_boundary(score, expected_category):
    assert _risk_category(score) == expected_category


def test_risk_category_thresholds_constant_covers_0_to_100_with_no_gaps():
    categories = [_risk_category(s) for s in range(101)]
    assert categories[0] == "low"
    assert categories[100] == "critical"
    # Monotonic: risk category never gets "less severe" as the score rises.
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    assert all(order[categories[i]] <= order[categories[i + 1]] for i in range(100))


def test_risk_category_thresholds_are_exactly_what_this_module_documents():
    assert RISK_CATEGORY_THRESHOLDS == (
        ("critical", 75), ("high", 50), ("medium", 25), ("low", 0),
    )


# -- breakdown shape ----------------------------------------------------------


def test_breakdown_carries_every_factor_with_weight_and_contribution():
    result = compute_device_risk(CLEAN_INPUTS)
    breakdown = result["breakdown"]
    assert set(breakdown.keys()) == set(WEIGHTS.keys())
    for name, entry in breakdown.items():
        assert entry["weight"] == WEIGHTS[name]
        assert entry["contribution"] == pytest.approx(entry["normalized"] * entry["weight"], abs=0.05)


def test_criticality_and_exposure_levels_constants_match_the_db_check_constraints():
    # lab/auditor/db/init.sql's devices.criticality/exposure CHECK constraints
    # must stay in sync with these - if either drifts, PATCH /devices/{id}
    # would accept a value this engine can't score, or reject one it could.
    assert CRITICALITY_LEVELS == ("low", "medium", "high", "critical")
    assert EXPOSURE_LEVELS == ("none", "internal_only", "internet_facing")
