from policies.nca.checklists import evaluate_checklist

STRATEGY_RULE = [
    {
        "conditions": [
            {"field": "answers.strategy_exists", "op": "equals", "value": False},
        ],
        "suggested_status": "fail",
    },
    {
        "conditions": [
            {"field": "answers.strategy_exists", "op": "equals", "value": True},
            {"field": "answers.approved_by_leadership", "op": "equals", "value": False},
        ],
        "suggested_status": "partial",
    },
    {
        "conditions": [
            {"field": "answers.strategy_exists", "op": "equals", "value": True},
            {"field": "answers.approved_by_leadership", "op": "equals", "value": True},
        ],
        "suggested_status": "pass",
    },
]


def test_first_matching_rule_wins():
    assert evaluate_checklist(STRATEGY_RULE, {"strategy_exists": False}) == "fail"


def test_and_semantics_require_every_condition_in_a_rule():
    result = evaluate_checklist(
        STRATEGY_RULE, {"strategy_exists": True, "approved_by_leadership": False}
    )
    assert result == "partial"


def test_full_pass_requires_all_conditions_true():
    result = evaluate_checklist(
        STRATEGY_RULE, {"strategy_exists": True, "approved_by_leadership": True}
    )
    assert result == "pass"


def test_missing_answer_never_crashes_and_never_matches():
    # No answers submitted at all - every rule's conditions reference a
    # missing field, so nothing matches; this must never be treated as a pass.
    assert evaluate_checklist(STRATEGY_RULE, {}) is None


def test_no_matching_rule_returns_none_not_a_guessed_status():
    rule = [
        {
            "conditions": [{"field": "answers.x", "op": "equals", "value": "unreachable"}],
            "suggested_status": "fail",
        },
    ]
    assert evaluate_checklist(rule, {"x": "something else"}) is None


def test_empty_suggestion_rule_returns_none():
    assert evaluate_checklist([], {"anything": True}) is None
