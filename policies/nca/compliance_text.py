"""Fixed compliance-language strings shared by lab/auditor/api/nca_routes.py
and lab/auditor/api/nca_report.py, so the wording only lives in one place and
every surface (API JSON, CSV exports, the executive PDF, the dashboard) says
exactly the same thing. Every string here is authored text, never model
output - this module has no LLM dependency and none of its callers may pass
these strings through one.
"""

PRODUCT_LABEL = "NCA CGIoT-1:2024 Alignment"

DISCLAIMER = (
    "This reflects an assessment of alignment with NCA CGIoT-1:2024 guidance. "
    "It is not an NCA certification, and CGIoT-1:2024 is guidance rather than "
    "a certifiable standard: a device or network scan alone cannot establish "
    "organizational compliance, since governance controls such as policy "
    "approval, personnel training, independent audits, and supplier or cloud "
    "contract compliance are not observable from a scan and are tracked here "
    "as separate manual assessments. Industrial IoT deployments may require a "
    "separate OTCC assessment. Cryptographic controls and cloud-hosted "
    "components may require additional mapping against the NCS and CCC "
    "control sets, which this module does not perform."
)

METHODOLOGY_TEXT = (
    "Device-scope controls are assessed from a combination of automated scan "
    "evidence (where policies/catalog/scan_tests.py already produces it, "
    "surfaced via a configurable finding-to-control mapping table) and manual "
    "reviewer attestation. Organizational-scope controls - domain 1 "
    "(governance) and the mobile, supplier, and cloud guideline groups - are "
    "manual-assessment-only: no automated mapping ever targets them, because "
    "a scan cannot demonstrate policy approval, training completion, audit "
    "outcomes, or supplier/cloud contract terms."
)

STATUS_DEFINITIONS = {
    "pass": "Every applicable required control passed, with evidence that has not expired.",
    "partial": "No applicable required control failed, but at least one is partial, not yet tested, or its evidence has expired.",
    "fail": "At least one applicable required control failed.",
    "not_tested": "No applicable required control has been assessed yet.",
}
