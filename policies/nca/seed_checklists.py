"""Guided checklists for the ~60 organizational/mobile/supplier/cloud NCA
guidelines no network or device scan can ever verify - see
policies/nca/checklists.py for how these get evaluated (a deterministic
rule, never an LLM), and docs/nca-compliance.md for the full rationale.

Every question is derived directly from its guideline's own canonical text
(policies/nca/catalog_1_2024.json) - never inventing a requirement the
standard doesn't state. This framework's own guideline wording recurs in a
small number of real, recognizable shapes ("define, document, approve, and
implement X", "periodically review... and update", "conduct/maintain X as
an ongoing practice") - three small reusable templates below capture those
shapes once rather than hand-authoring near-identical structure 60 times
independently, but every subject phrase is still specific to its own
guideline's real requirement, not a generic placeholder.

Committed as structured data (like catalog_1_2024.json), seeded the same
way seed_catalog.py/seed_finding_mappings.py already are - idempotent via
ON CONFLICT (control_id) DO UPDATE, safe to re-run after edits.
"""

import json

from policies.nca.build_catalog import control_id

QuestionsAndRule = tuple[list[dict], list[dict]]


def _define_approve_implement(subject: str) -> QuestionsAndRule:
    """Matches this framework's most common phrasing: "define, document,
    approve, and implement X". Fails outright if not even defined; a
    partial covers "defined but not fully approved/implemented yet"."""
    questions = [
        {"key": "defined", "label": f"Is {subject} defined and documented?", "type": "yes_no", "required": True},
        {"key": "approved", "label": f"Has {subject} been formally approved?", "type": "yes_no", "required": True},
        {"key": "implemented", "label": f"Is {subject} actually implemented in practice?", "type": "yes_no", "required": True},
    ]
    rule = [
        {"conditions": [{"field": "answers.defined", "op": "equals", "value": False}], "suggested_status": "fail"},
        {
            "conditions": [
                {"field": "answers.defined", "op": "equals", "value": True},
                {"field": "answers.approved", "op": "equals", "value": True},
                {"field": "answers.implemented", "op": "equals", "value": True},
            ],
            "suggested_status": "pass",
        },
        {"conditions": [{"field": "answers.defined", "op": "equals", "value": True}], "suggested_status": "partial"},
    ]
    return questions, rule


def _periodic_review(subject: str) -> QuestionsAndRule:
    """Matches this framework's other very common phrasing: "periodically
    review at planned intervals and if necessary, update X"."""
    questions = [
        {"key": "reviewed", "label": f"Has {subject} been reviewed within the last 12 months?", "type": "yes_no", "required": True},
        {
            "key": "updated",
            "label": "Were necessary updates made following that review (or was it confirmed none were needed)?",
            "type": "yes_no",
            "required": True,
        },
        {"key": "last_reviewed_on", "label": "Date of the last review", "type": "date", "required": False},
    ]
    rule = [
        {"conditions": [{"field": "answers.reviewed", "op": "equals", "value": False}], "suggested_status": "fail"},
        {
            "conditions": [
                {"field": "answers.reviewed", "op": "equals", "value": True},
                {"field": "answers.updated", "op": "equals", "value": True},
            ],
            "suggested_status": "pass",
        },
        {"conditions": [{"field": "answers.reviewed", "op": "equals", "value": True}], "suggested_status": "partial"},
    ]
    return questions, rule


def _practice_with_evidence(subject: str) -> QuestionsAndRule:
    """Matches guidelines phrased as an ongoing practice/activity rather
    than a define-approve-implement triad (e.g. "conduct X", "maintain X",
    "review X during Y") - the practice must be real AND evidenced, not
    just claimed."""
    questions = [
        {"key": "practiced", "label": f"Is {subject} actually being carried out in practice?", "type": "yes_no", "required": True},
        {
            "key": "evidenced",
            "label": "Is there documented evidence of this (records, reports, logs)?",
            "type": "yes_no",
            "required": True,
        },
    ]
    rule = [
        {"conditions": [{"field": "answers.practiced", "op": "equals", "value": False}], "suggested_status": "fail"},
        {
            "conditions": [
                {"field": "answers.practiced", "op": "equals", "value": True},
                {"field": "answers.evidenced", "op": "equals", "value": True},
            ],
            "suggested_status": "pass",
        },
        {"conditions": [{"field": "answers.practiced", "op": "equals", "value": True}], "suggested_status": "partial"},
    ]
    return questions, rule


# guideline_id -> (template_fn, subject phrase drawn from that guideline's
# own canonical_requirement text in catalog_1_2024.json).
CHECKLIST_SPECS: dict[str, tuple] = {
    # Domain 1 - Cybersecurity Governance (all 27 guidelines)
    "1-1-1": (_define_approve_implement, "an IoT cybersecurity strategy within the organization's overall cybersecurity strategy"),
    "1-1-2": (_define_approve_implement, "an IoT cybersecurity plan outlining prioritized actions and initiatives"),
    "1-1-3": (_practice_with_evidence, "defining and tracking IoT cybersecurity KPIs"),
    "1-1-4": (_periodic_review, "the IoT cybersecurity strategic initiatives and goals"),
    "1-2-1": (_define_approve_implement, "IoT cybersecurity policies and procedures, disseminated to relevant internal and external parties"),
    "1-2-2": (_define_approve_implement, "technical security standards supporting the IoT cybersecurity policies (hardening, authentication/authorization, certificates, network zoning)"),
    "1-2-3": (_periodic_review, "the IoT cybersecurity policies, procedures, and standards"),
    "1-3-1": (_define_approve_implement, "IoT cybersecurity roles and responsibilities"),
    "1-3-2": (_periodic_review, "the IoT cybersecurity roles and responsibilities"),
    "1-4-1": (_define_approve_implement, "IoT cybersecurity risk management practices"),
    "1-4-2": (_practice_with_evidence, "defining a list of common IoT cybersecurity risk scenarios"),
    "1-4-3": (_practice_with_evidence, "documenting IoT cybersecurity risks in the risk register"),
    "1-4-4": (_practice_with_evidence, "conducting an IoT cybersecurity risk assessment"),
    "1-4-5": (_practice_with_evidence, "identifying risks exceeding the defined appetite and their mitigation measures"),
    "1-4-6": (_periodic_review, "the IoT cybersecurity risk management procedures and practices"),
    "1-5-1": (_practice_with_evidence, "Secure-by-Design practices throughout the IoT development lifecycle"),
    "1-5-2": (_practice_with_evidence, "reviewing IoT cybersecurity requirements during project planning and design"),
    "1-5-3": (_define_approve_implement, "a change management procedure for the IoT cybersecurity posture"),
    "1-6-1": (_practice_with_evidence, "enforcement/compliance mechanisms for IoT cybersecurity laws and regulations"),
    "1-7-1": (_practice_with_evidence, "periodic review of IoT cybersecurity requirement implementation by the cybersecurity function"),
    "1-7-2": (_practice_with_evidence, "independent or third-party audit of IoT cybersecurity requirements"),
    "1-7-3": (_define_approve_implement, "a process to record and manage IoT cybersecurity non-compliance"),
    "1-8-1": (_define_approve_implement, "IoT cybersecurity requirements for personnel (pre/during/post-employment)"),
    "1-8-2": (_periodic_review, "personnel access to IoT devices and services"),
    "1-8-3": (_periodic_review, "the IoT cybersecurity requirements for personnel"),
    "1-9-1": (_define_approve_implement, "an IoT-specific cybersecurity awareness and training strategy"),
    "1-9-2": (_practice_with_evidence, "organization-wide IoT cybersecurity awareness promotion"),
    # Domain 2 - organizational-scope subdomains (device-testable ones are
    # classified separately in build_catalog.py's DEVICE_TESTABLE_GUIDELINES)
    "2-1-1": (_practice_with_evidence, "maintaining an inventory of IoT devices/services assets"),
    "2-1-2": (_periodic_review, "the IoT asset inventory"),
    "2-2-3": (_periodic_review, "IoT access identities and permissions"),
    "2-3-1": (_define_approve_implement, "cybersecurity requirements for data transmitted between IoT devices and email/messaging services"),
    "2-3-2": (_practice_with_evidence, "implementing the email/messaging data-protection requirements"),
    "2-4-1": (_define_approve_implement, "cybersecurity requirements for secure IoT connectivity to its usage environment"),
    "2-4-4": (_practice_with_evidence, "logical/physical segregation between the IoT environment and the organization's environment"),
    "2-6-1": (_practice_with_evidence, "IoT data classification and labeling mechanisms"),
    "2-7-1": (_define_approve_implement, "cybersecurity requirements for IoT data per the National Cryptographic Standards (NCS-1:2020)"),
    "2-8-1": (_define_approve_implement, "IoT cybersecurity requirements for backup and recovery management"),
    "2-8-2": (_practice_with_evidence, "maintaining a tested, trusted local backup of IoT software and data"),
    "2-8-3": (_periodic_review, "the stored IoT backups, including testing them"),
    "2-10-1": (_practice_with_evidence, "IoT-specific penetration testing"),
    "2-10-2": (_practice_with_evidence, "red team exercises against mission-critical IoT devices/services"),
    "2-12-1": (_practice_with_evidence, "an IoT incident/threat model incorporated into overall incident management"),
    "2-12-2": (_define_approve_implement, "an IoT cybersecurity incident management plan"),
    "2-12-3": (_practice_with_evidence, "a post-incident analysis capability for IoT devices"),
    "2-12-4": (_define_approve_implement, "IoT-specific threat management requirements"),
    "2-13-1": (_practice_with_evidence, "physical detection systems monitoring the critical IoT physical environment"),
    "2-14-3": (_practice_with_evidence, "secure code development practices and source code review for IoT applications"),
    "2-14-4": (_periodic_review, "the whitelisted IoT applications"),
    # Mobile (1)
    "2-5-1": (_practice_with_evidence, "the required measures for IoT-connected mobile devices (secure comms, restricted access, secure auth, secure mobile-app development, secure erasure on loss)"),
    # Supplier (6)
    "4-1-1": (_define_approve_implement, "IoT cybersecurity requirements within supply chain/third-party contracts"),
    "4-1-2": (_practice_with_evidence, "requiring manufacturers/service providers to demonstrate Secure-by-Design cybersecurity capabilities"),
    "4-1-3": (_practice_with_evidence, "requiring a hardware/software component list from developers/manufacturers"),
    "4-1-4": (_practice_with_evidence, "identifying supply-chain IoT systems/components for the risk assessment"),
    "4-1-5": (_practice_with_evidence, "verifying (audits, testing, certification) third-party IoT component compliance"),
    "4-1-6": (_periodic_review, "supply-chain IoT risk mitigation procedures and cybersecurity requirements"),
    # Cloud (5)
    "4-2-1": (_define_approve_implement, "cybersecurity requirements for cloud services hosting IoT, including applicable Cloud Cybersecurity Controls (CCC)"),
    "4-2-2": (_practice_with_evidence, "authorization/authentication/verification/encryption controls for IoT devices interacting with the cloud service"),
    "4-2-3": (_practice_with_evidence, "assessing the cloud/managed service provider's cybersecurity posture"),
    "4-2-4": (_define_approve_implement, "procedures for cloud cybersecurity audits, monitoring, and multi-tenant risk management"),
    "4-2-5": (_practice_with_evidence, "contractual provisions for vendor-neutral data portability on cloud-provider exit"),
}


def _build_all() -> list[dict]:
    entries = []
    for guideline_id, (template_fn, subject) in CHECKLIST_SPECS.items():
        questions, rule = template_fn(subject)
        entries.append({"control_id": control_id(guideline_id), "questions": questions, "suggestion_rule": rule})
    return entries


CHECKLISTS = _build_all()


def seed(conn) -> int:
    upserted = 0
    for entry in CHECKLISTS:
        result = conn.execute(
            """
            INSERT INTO compliance_control_checklists (control_id, questions, suggestion_rule)
            VALUES (%(control_id)s, %(questions)s, %(suggestion_rule)s)
            ON CONFLICT (control_id) DO UPDATE SET
                questions = EXCLUDED.questions,
                suggestion_rule = EXCLUDED.suggestion_rule,
                updated_at = now()
            """,
            {
                **entry,
                "questions": json.dumps(entry["questions"]),
                "suggestion_rule": json.dumps(entry["suggestion_rule"]),
            },
        )
        if result.rowcount != 0:
            upserted += 1
    conn.commit()
    return upserted


if __name__ == "__main__":
    import os

    import psycopg

    url = os.environ["DATABASE_URL"]
    connection = psycopg.connect(url)
    try:
        print(f"Upserted {seed(connection)} checklists")
    finally:
        connection.close()
