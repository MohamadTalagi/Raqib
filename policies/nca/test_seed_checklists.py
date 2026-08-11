import json
from pathlib import Path

from policies.nca.build_catalog import CLOUD_GUIDELINES, MOBILE_GUIDELINES, SUPPLIER_GUIDELINES
from policies.nca.checklists import evaluate_checklist
from policies.nca.seed_checklists import CHECKLIST_SPECS, CHECKLISTS

VALID_STATUSES = {"pass", "partial", "fail", "not_tested", "review_required"}

CATALOG_PATH = Path(__file__).resolve().parent / "catalog_1_2024.json"


def _non_device_guideline_ids() -> set[str]:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    return {
        g["guideline_id"]
        for g in catalog["guidelines"]
        if g["scope_type"] in ("organization", "mobile", "supplier", "cloud")
    }


def test_every_non_device_guideline_has_a_checklist():
    # Locks down full coverage of the organizational/mobile/supplier/cloud
    # guidelines - catches a future guideline reclassification or catalog
    # change leaving a gap silently unnoticed. It did exactly that when 2-1-1
    # moved to device scope and its now-unreachable checklist was left behind.
    assert set(CHECKLIST_SPECS.keys()) == _non_device_guideline_ids()


def test_every_checklist_has_at_least_one_required_question():
    for entry in CHECKLISTS:
        assert entry["questions"], entry["control_id"]
        assert any(q["required"] for q in entry["questions"]), entry["control_id"]


def test_every_question_key_is_unique_within_its_checklist():
    for entry in CHECKLISTS:
        keys = [q["key"] for q in entry["questions"]]
        assert len(keys) == len(set(keys)), entry["control_id"]


def test_every_question_type_is_a_real_supported_type():
    for entry in CHECKLISTS:
        for question in entry["questions"]:
            assert question["type"] in ("yes_no", "text", "date"), (entry["control_id"], question["key"])


def test_every_rule_condition_references_a_real_question_key():
    for entry in CHECKLISTS:
        question_keys = {q["key"] for q in entry["questions"]}
        for rule in entry["suggestion_rule"]:
            for condition in rule["conditions"]:
                field = condition["field"]
                assert field.startswith("answers."), (entry["control_id"], field)
                assert field.removeprefix("answers.") in question_keys, (entry["control_id"], field)


def test_every_rule_suggests_a_real_status():
    for entry in CHECKLISTS:
        for rule in entry["suggestion_rule"]:
            assert rule["suggested_status"] in VALID_STATUSES, (entry["control_id"], rule["suggested_status"])


def test_every_checklist_can_reach_pass_partial_and_fail():
    # Confirms each authored rule is a real 3-tier ladder, not a rule that
    # can only ever produce one outcome regardless of the answers given.
    for entry in CHECKLISTS:
        reachable = {rule["suggested_status"] for rule in entry["suggestion_rule"]}
        assert {"pass", "partial", "fail"} <= reachable, entry["control_id"]


def test_a_negative_answer_to_the_first_question_always_suggests_fail():
    # Every template's first question is the "does this even exist at all"
    # gate - answering it negatively must never still suggest a pass.
    for entry in CHECKLISTS:
        first_key = entry["questions"][0]["key"]
        result = evaluate_checklist(entry["suggestion_rule"], {first_key: False})
        assert result == "fail", entry["control_id"]


def test_all_yes_answers_suggest_pass():
    for entry in CHECKLISTS:
        answers = {q["key"]: True for q in entry["questions"] if q["type"] == "yes_no"}
        result = evaluate_checklist(entry["suggestion_rule"], answers)
        assert result == "pass", entry["control_id"]


def test_domain_1_governance_is_fully_covered():
    domain_1_ids = {f"1-{sub}-{item}" for sub, item in [
        (1, 1), (1, 2), (1, 3), (1, 4),
        (2, 1), (2, 2), (2, 3),
        (3, 1), (3, 2),
        (4, 1), (4, 2), (4, 3), (4, 4), (4, 5), (4, 6),
        (5, 1), (5, 2), (5, 3),
        (6, 1),
        (7, 1), (7, 2), (7, 3),
        (8, 1), (8, 2), (8, 3),
        (9, 1), (9, 2),
    ]}
    assert domain_1_ids <= set(CHECKLIST_SPECS.keys())


def test_mobile_supplier_cloud_are_fully_covered():
    from policies.nca.build_catalog import control_id

    covered = set(CHECKLIST_SPECS.keys())
    for guideline_id in MOBILE_GUIDELINES | SUPPLIER_GUIDELINES | CLOUD_GUIDELINES:
        assert guideline_id in covered, guideline_id
        assert control_id(guideline_id)  # sanity: resolves without raising
