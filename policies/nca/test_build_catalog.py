from policies.nca.build_catalog import (
    FRAMEWORK,
    FRAMEWORK_VERSION,
    build_catalog,
    build_manufacturer_principles,
)

EXPECTED_SUBDOMAINS = {
    "1-1": "Cybersecurity Strategy",
    "1-2": "Cybersecurity Policies and Procedures",
    "1-3": "Cybersecurity Roles and Responsibilities",
    "1-4": "Cybersecurity Risk Management",
    "1-5": "Cybersecurity in Information and Technology Project Management",
    "1-6": "Compliance with Cybersecurity Standards, Laws and Regulations",
    "1-7": "Periodical Cybersecurity Review and Audit",
    "1-8": "Cybersecurity in Human Resources",
    "1-9": "Cybersecurity Awareness and Training Program",
    "2-1": "Asset Management",
    "2-2": "Identity and Access Management",
    "2-3": "Email and Messaging Services Protection",
    "2-4": "Network Security Management",
    "2-5": "IoT-Connected Mobile Devices Security",
    "2-6": "Data and Information Protection",
    "2-7": "Cryptography",
    "2-8": "Backup and Recovery Management",
    "2-9": "Vulnerability Management",
    "2-10": "Penetration Testing",
    "2-11": "Cybersecurity Event Logs and Monitoring Management",
    "2-12": "Cybersecurity Incident and Threat Management",
    "2-13": "Physical Security",
    "2-14": "IoT Application Security",
    "2-15": "IoT Device Lifecycle Management",
    "3-1": "Cybersecurity Resilience Aspects of Business Continuity Management",
    "4-1": "Third-Party Cybersecurity",
    "4-2": "Cloud Computing and Hosting Cybersecurity",
}


def test_catalog_has_exactly_81_guidelines():
    catalog = build_catalog()
    assert len(catalog) == 81


def test_all_27_subdomains_present_with_exact_names():
    catalog = build_catalog()
    by_subdomain = {g["subdomain_id"]: g["subdomain_name"] for g in catalog}
    assert by_subdomain == EXPECTED_SUBDOMAINS


def test_no_duplicate_guideline_ids():
    catalog = build_catalog()
    ids = [g["guideline_id"] for g in catalog]
    assert len(ids) == len(set(ids))


def test_no_duplicate_primary_keys():
    catalog = build_catalog()
    ids = [g["id"] for g in catalog]
    assert len(ids) == len(set(ids))


def test_every_entry_has_nonempty_canonical_requirement():
    catalog = build_catalog()
    for entry in catalog:
        assert entry["canonical_requirement"].strip(), entry["guideline_id"]
        assert entry["implementation_summary"].strip(), entry["guideline_id"]


def test_canonical_requirement_is_never_the_placeholder_word_missing():
    # "Never invent missing NCA wording" - if extraction ever fails silently,
    # it must not produce a fabricated placeholder that looks legitimate.
    catalog = build_catalog()
    for entry in catalog:
        assert "MISSING" not in entry["canonical_requirement"].upper()


def test_every_entry_has_framework_metadata_and_required_fields():
    catalog = build_catalog()
    for entry in catalog:
        assert entry["framework"] == FRAMEWORK
        assert entry["framework_version"] == FRAMEWORK_VERSION
        assert entry["scope_type"] in {"organization", "device", "mobile", "supplier", "cloud"}
        assert entry["assessment_type"] in {"automated", "manual", "hybrid"}
        assert entry["severity"] in {"low", "medium", "high", "critical"}
        assert isinstance(entry["required"], bool)
        assert isinstance(entry["enabled"], bool)


def test_critical_severity_is_reachable_and_disjoint_from_high():
    # _severity() used to only ever return "high"/"medium" - no real
    # guideline was ever "critical", which made
    # evaluator.py::overall_classification's critical-failure-downgrade
    # branch (Passed -> Partially Passed) permanently dead code against
    # real data. These 3 are IoTGuard's own judgment call (see
    # build_catalog.py's CRITICAL_SEVERITY_GUIDELINES docstring) - serious
    # enough to downgrade a high score, but deliberately not part of
    # BLOCKING_GUIDELINES (which forces FAILED outright).
    catalog = build_catalog()
    by_id = {g["guideline_id"]: g for g in catalog}
    for guideline_id in ("2-9-1", "2-9-2", "2-15-1"):
        assert by_id[guideline_id]["severity"] == "critical"
    # A representative high-severity guideline is unaffected by the change.
    assert by_id["2-2-2"]["severity"] == "high"
    # No guideline is ever double-classified across tiers.
    critical_ids = {g["guideline_id"] for g in catalog if g["severity"] == "critical"}
    high_ids = {g["guideline_id"] for g in catalog if g["severity"] == "high"}
    assert critical_ids.isdisjoint(high_ids)


def test_known_device_testable_guideline_is_classified_correctly():
    catalog = build_catalog()
    by_id = {g["guideline_id"]: g for g in catalog}
    assert by_id["2-2-2"]["scope_type"] == "device"
    assert by_id["2-2-2"]["assessment_type"] == "automated"
    # 2-2-2's canonical wording (from the standard) must mention hard-coded
    # passwords verbatim - this is the exact clause the default-creds finding
    # mapping targets.
    assert "hard-coded passwords" in by_id["2-2-2"]["canonical_requirement"]


def test_organizational_only_guideline_is_never_marked_automated():
    # 1-1-1 (cybersecurity strategy approval) cannot be inferred from a scan.
    catalog = build_catalog()
    by_id = {g["guideline_id"]: g for g in catalog}
    assert by_id["1-1-1"]["scope_type"] == "organization"
    assert by_id["1-1-1"]["assessment_type"] == "manual"


def test_source_page_is_present_for_every_guideline():
    catalog = build_catalog()
    for entry in catalog:
        assert entry["source_page"], entry["guideline_id"]


def test_manufacturer_principles_extracted_and_match_the_brief_examples():
    principles = build_manufacturer_principles()
    assert len(principles) == 11
    by_number = {p["number"]: p["wording"] for p in principles}
    assert "hard-coded password" in by_number[5]
    assert "Only enable software services" in by_number[3]
    assert "**" not in by_number[5]
