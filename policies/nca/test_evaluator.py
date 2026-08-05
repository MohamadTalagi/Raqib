from policies.nca.evaluator import (
    device_overall_status,
    device_score,
    domain_summary,
    effective_status,
    has_blocking_failure,
    is_effectively_applicable,
    overall_classification,
)


def _row(
    control_id="2-2-2",
    domain_id="2",
    required=True,
    status="pass",
    applicability="applicable",
    evidence_expired=False,
    exception_active=False,
    severity="medium",
    blocking=False,
):
    return {
        "control_id": control_id,
        "domain_id": domain_id,
        "required": required,
        "status": status,
        "applicability": applicability,
        "evidence_expired": evidence_expired,
        "exception_active": exception_active,
        "severity": severity,
        "blocking": blocking,
    }


# ---------------------------------------------------------------------------
# effective_status
# ---------------------------------------------------------------------------


def test_effective_status_pass_with_current_evidence_stays_pass():
    assert effective_status(_row(status="pass", evidence_expired=False)) == "pass"


def test_effective_status_pass_with_expired_evidence_rolls_to_partial():
    assert effective_status(_row(status="pass", evidence_expired=True)) == "partial"


def test_effective_status_fail_is_never_changed_by_evidence_expiry():
    assert effective_status(_row(status="fail", evidence_expired=True)) == "fail"


def test_effective_status_partial_is_never_changed_by_evidence_expiry():
    assert effective_status(_row(status="partial", evidence_expired=True)) == "partial"


def test_effective_status_not_tested_is_never_changed_by_evidence_expiry():
    assert effective_status(_row(status="not_tested", evidence_expired=True)) == "not_tested"


# ---------------------------------------------------------------------------
# is_effectively_applicable
# ---------------------------------------------------------------------------


def test_applicable_control_with_no_exception_is_effectively_applicable():
    assert is_effectively_applicable(_row(applicability="applicable")) is True


def test_not_applicable_control_is_never_effectively_applicable():
    assert is_effectively_applicable(_row(applicability="not_applicable")) is False


def test_applicable_control_with_active_exception_is_excluded():
    assert is_effectively_applicable(_row(applicability="applicable", exception_active=True)) is False


def test_not_applicable_control_with_no_exception_is_still_excluded():
    assert is_effectively_applicable(_row(applicability="not_applicable", exception_active=False)) is False


# ---------------------------------------------------------------------------
# device_overall_status
# ---------------------------------------------------------------------------


def test_overall_status_pass_when_every_applicable_required_control_passes():
    rows = [_row(control_id="a", status="pass"), _row(control_id="b", status="pass")]
    assert device_overall_status(rows) == "pass"


def test_overall_status_fail_when_any_applicable_required_control_fails():
    rows = [_row(control_id="a", status="pass"), _row(control_id="b", status="fail")]
    assert device_overall_status(rows) == "fail"


def test_overall_status_partial_when_no_failures_but_one_partial():
    rows = [_row(control_id="a", status="pass"), _row(control_id="b", status="partial")]
    assert device_overall_status(rows) == "partial"


def test_overall_status_partial_when_no_failures_but_one_not_tested_among_others():
    rows = [_row(control_id="a", status="pass"), _row(control_id="b", status="not_tested")]
    assert device_overall_status(rows) == "partial"


def test_overall_status_partial_when_no_failures_but_expired_evidence_on_a_pass():
    rows = [
        _row(control_id="a", status="pass"),
        _row(control_id="b", status="pass", evidence_expired=True),
    ]
    assert device_overall_status(rows) == "partial"


def test_overall_status_fail_takes_precedence_over_partial():
    rows = [
        _row(control_id="a", status="fail"),
        _row(control_id="b", status="partial"),
        _row(control_id="c", status="not_tested"),
    ]
    assert device_overall_status(rows) == "fail"


def test_overall_status_not_tested_when_zero_applicable_required_rows_exist():
    # Nothing has ever been assessed for this device - distinct from "partial".
    assert device_overall_status([]) == "not_tested"


def test_overall_status_not_tested_when_only_optional_controls_have_rows():
    rows = [_row(control_id="a", status="fail", required=False)]
    assert device_overall_status(rows) == "not_tested"


def test_overall_status_not_tested_when_every_applicable_required_row_is_not_tested():
    # Regression: the real caller (nca_routes._evaluator_rows_for_scope)
    # always supplies one row per enabled control, defaulting an untouched
    # control to status="not_tested" rather than omitting it - so a device
    # that has never been assessed at all produces a FULL list of
    # not_tested rows, not an empty one. This must still read as
    # "not_tested" ("Not Assessed"), not "partial".
    rows = [
        _row(control_id="a", status="not_tested"),
        _row(control_id="b", status="not_tested"),
        _row(control_id="c", status="not_tested"),
    ]
    assert device_overall_status(rows) == "not_tested"


def test_overall_status_partial_when_some_assessed_and_some_still_not_tested():
    # A device with at least one real result mixed with untouched controls
    # is genuinely partial, unlike the all-not_tested case above.
    rows = [
        _row(control_id="a", status="pass"),
        _row(control_id="b", status="not_tested"),
    ]
    assert device_overall_status(rows) == "partial"


def test_overall_status_excludes_approved_not_applicable_from_denominator():
    rows = [
        _row(control_id="a", status="pass"),
        _row(control_id="b", status="fail", applicability="not_applicable"),
    ]
    assert device_overall_status(rows) == "pass"


def test_overall_status_excludes_controls_with_active_exception_from_denominator():
    rows = [
        _row(control_id="a", status="pass"),
        _row(control_id="b", status="fail", exception_active=True),
    ]
    assert device_overall_status(rows) == "pass"


def test_overall_status_optional_controls_never_affect_result():
    rows = [
        _row(control_id="a", status="pass", required=True),
        _row(control_id="b", status="fail", required=False),
    ]
    assert device_overall_status(rows) == "pass"


# ---------------------------------------------------------------------------
# device_score
# ---------------------------------------------------------------------------


def test_score_is_none_when_denominator_is_empty():
    assert device_score([]) is None


def test_score_is_none_when_only_optional_controls_exist():
    assert device_score([_row(status="pass", required=False)]) is None


def test_score_is_none_when_every_applicable_required_row_is_not_tested():
    rows = [_row(control_id="a", status="not_tested"), _row(control_id="b", status="not_tested")]
    assert device_score(rows) is None


def test_score_is_100_when_all_applicable_required_pass():
    rows = [_row(control_id="a", status="pass"), _row(control_id="b", status="pass")]
    assert device_score(rows) == 100


def test_score_is_0_when_all_applicable_required_fail():
    rows = [_row(control_id="a", status="fail"), _row(control_id="b", status="fail")]
    assert device_score(rows) == 0


def test_score_rounds_fractional_result():
    rows = [
        _row(control_id="a", status="pass"),
        _row(control_id="b", status="pass"),
        _row(control_id="c", status="fail"),
    ]
    assert device_score(rows) == 67  # 2/3 -> 66.67 -> 67


def test_score_treats_expired_evidence_pass_as_not_passed():
    rows = [_row(control_id="a", status="pass", evidence_expired=True)]
    assert device_score(rows) == 0


def test_score_excludes_not_applicable_and_excepted_controls_from_denominator():
    rows = [
        _row(control_id="a", status="pass"),
        _row(control_id="b", status="fail", applicability="not_applicable"),
        _row(control_id="c", status="fail", exception_active=True),
    ]
    assert device_score(rows) == 100


def test_score_never_reaches_100_with_an_unresolved_failure_present():
    rows = [_row(control_id="a", status="pass"), _row(control_id="b", status="fail")]
    assert device_score(rows) == 50


# ---------------------------------------------------------------------------
# domain_summary
# ---------------------------------------------------------------------------


def test_domain_summary_counts_across_all_four_groups():
    rows = [
        _row(control_id="a", domain_id="1", status="pass"),
        _row(control_id="b", domain_id="2", status="fail"),
        _row(control_id="c", domain_id="3", status="partial"),
        _row(control_id="d", domain_id="4", status="not_tested"),
    ]
    summary = domain_summary(rows)
    assert summary["Cybersecurity Governance"]["pass"] == 1
    assert summary["Cybersecurity Defense"]["fail"] == 1
    assert summary["Cybersecurity Resilience"]["partial"] == 1
    assert summary["Third-Party and Cloud Computing Cybersecurity"]["not_tested"] == 1


def test_domain_summary_includes_optional_controls_unlike_score():
    rows = [_row(control_id="a", domain_id="1", status="pass", required=False)]
    summary = domain_summary(rows)
    assert summary["Cybersecurity Governance"]["pass"] == 1


def test_domain_summary_excludes_not_applicable_controls():
    rows = [_row(control_id="a", domain_id="1", status="fail", applicability="not_applicable")]
    summary = domain_summary(rows)
    assert summary["Cybersecurity Governance"]["fail"] == 0


def test_domain_summary_excludes_controls_with_active_exception():
    rows = [_row(control_id="a", domain_id="1", status="fail", exception_active=True)]
    summary = domain_summary(rows)
    assert summary["Cybersecurity Governance"]["fail"] == 0


def test_domain_summary_applies_expired_evidence_rollup():
    rows = [_row(control_id="a", domain_id="1", status="pass", evidence_expired=True)]
    summary = domain_summary(rows)
    assert summary["Cybersecurity Governance"]["partial"] == 1
    assert summary["Cybersecurity Governance"]["pass"] == 0


def test_domain_summary_returns_all_four_groups_even_when_empty():
    summary = domain_summary([])
    assert set(summary.keys()) == {
        "Cybersecurity Governance",
        "Cybersecurity Defense",
        "Cybersecurity Resilience",
        "Third-Party and Cloud Computing Cybersecurity",
    }
    for bucket in summary.values():
        assert bucket == {"pass": 0, "partial": 0, "fail": 0, "not_tested": 0, "review_required": 0}


# ---------------------------------------------------------------------------
# review_required status
# ---------------------------------------------------------------------------


def test_overall_status_partial_when_a_control_is_review_required():
    rows = [_row(control_id="a", status="pass"), _row(control_id="b", status="review_required")]
    assert device_overall_status(rows) == "partial"


def test_score_treats_review_required_as_not_passed():
    rows = [_row(control_id="a", status="review_required")]
    assert device_score(rows) == 0


def test_domain_summary_counts_review_required_in_its_own_bucket():
    rows = [_row(control_id="a", domain_id="1", status="review_required")]
    summary = domain_summary(rows)
    assert summary["Cybersecurity Governance"]["review_required"] == 1
    assert summary["Cybersecurity Governance"]["partial"] == 0


# ---------------------------------------------------------------------------
# has_blocking_failure
# ---------------------------------------------------------------------------


def test_has_blocking_failure_empty_when_no_blocking_control_fails():
    rows = [_row(control_id="a", status="fail", blocking=False)]
    assert has_blocking_failure(rows) == []


def test_has_blocking_failure_returns_the_offending_row_when_blocking_control_fails():
    rows = [_row(control_id="a", status="fail", blocking=True)]
    result = has_blocking_failure(rows)
    assert [r["control_id"] for r in result] == ["a"]


def test_has_blocking_failure_ignores_a_blocking_control_that_passed():
    rows = [_row(control_id="a", status="pass", blocking=True)]
    assert has_blocking_failure(rows) == []


def test_has_blocking_failure_ignores_not_applicable_blocking_control():
    rows = [_row(control_id="a", status="fail", blocking=True, applicability="not_applicable")]
    assert has_blocking_failure(rows) == []


def test_has_blocking_failure_ignores_excepted_blocking_control():
    rows = [_row(control_id="a", status="fail", blocking=True, exception_active=True)]
    assert has_blocking_failure(rows) == []


# ---------------------------------------------------------------------------
# overall_classification
# ---------------------------------------------------------------------------


def test_classification_passed_at_high_score_with_no_issues():
    rows = [_row(control_id=f"c{i}", status="pass") for i in range(10)]
    result = overall_classification(rows)
    assert result["classification"] == "passed"
    assert result["score"] == 100


def test_classification_failed_when_blocking_control_fails_even_at_high_score():
    rows = [_row(control_id=f"c{i}", status="pass") for i in range(9)]
    rows.append(_row(control_id="blocker", status="fail", blocking=True))
    result = overall_classification(rows)
    assert result["classification"] == "failed"
    assert result["blocking_control_ids"] == ["blocker"]


def test_classification_partially_passed_when_high_score_but_critical_failure():
    rows = [_row(control_id=f"c{i}", status="pass") for i in range(9)]
    rows.append(_row(control_id="crit", status="fail", severity="critical"))
    result = overall_classification(rows)
    assert result["classification"] == "partially_passed"
    assert result["critical_failure_control_ids"] == ["crit"]


def test_classification_partially_passed_when_a_real_critical_guideline_fails():
    # Same scenario as the hand-constructed test above, but proving the
    # whole real path (catalog -> evaluator) together: 2-9-1 is one of
    # build_catalog.py's real CRITICAL_SEVERITY_GUIDELINES, not a synthetic
    # severity value a test invented. Before that catalog fix, no real
    # guideline_id could ever exercise this branch.
    from policies.nca.build_catalog import build_catalog

    catalog = {g["guideline_id"]: g for g in build_catalog()}
    assert catalog["2-9-1"]["severity"] == "critical"

    rows = [_row(control_id=f"c{i}", status="pass") for i in range(9)]
    rows.append(_row(control_id="NCA-CGIoT-1_2024-2-9-1", status="fail", severity=catalog["2-9-1"]["severity"]))
    result = overall_classification(rows)
    assert result["classification"] == "partially_passed"
    assert result["critical_failure_control_ids"] == ["NCA-CGIoT-1_2024-2-9-1"]


def test_classification_failed_when_score_below_partial_threshold():
    rows = [_row(control_id="a", status="pass"), _row(control_id="b", status="fail")]
    result = overall_classification(rows)  # 50% score, but partial_threshold default is 50 -> not below
    assert result["classification"] == "partially_passed"

    rows = [_row(control_id="a", status="fail"), _row(control_id="b", status="fail")]
    result = overall_classification(rows)  # 0%
    assert result["classification"] == "failed"


def test_classification_partially_passed_in_the_score_band_between_thresholds():
    rows = [
        _row(control_id="a", status="pass"),
        _row(control_id="b", status="pass"),
        _row(control_id="c", status="fail"),
    ]
    result = overall_classification(rows)  # 67%
    assert result["classification"] == "partially_passed"


def test_classification_failed_when_all_controls_not_applicable():
    rows = [_row(control_id="a", status="fail", applicability="not_applicable")]
    result = overall_classification(rows)
    assert result["classification"] == "failed"
    assert result["score"] is None


def test_classification_failed_when_nothing_has_ever_been_tested():
    rows = [_row(control_id="a", status="not_tested"), _row(control_id="b", status="not_tested")]
    result = overall_classification(rows)
    assert result["classification"] == "failed"
    assert result["score"] is None


def test_classification_partially_passed_when_mandatory_control_not_tested():
    rows = [_row(control_id=f"c{i}", status="pass") for i in range(9)]
    rows.append(_row(control_id="untested", status="not_tested"))
    result = overall_classification(rows)
    assert result["classification"] == "partially_passed"
    assert result["not_tested_control_ids"] == ["untested"]


def test_classification_partially_passed_when_mandatory_control_review_required():
    rows = [_row(control_id=f"c{i}", status="pass") for i in range(9)]
    rows.append(_row(control_id="review", status="review_required"))
    result = overall_classification(rows)
    assert result["classification"] == "partially_passed"
    assert result["review_required_control_ids"] == ["review"]


def test_classification_thresholds_are_configurable():
    rows = [_row(control_id="a", status="pass"), _row(control_id="b", status="fail")]  # 50%
    assert overall_classification(rows, partial_threshold=60)["classification"] == "failed"
    assert overall_classification(rows, partial_threshold=40)["classification"] == "partially_passed"
