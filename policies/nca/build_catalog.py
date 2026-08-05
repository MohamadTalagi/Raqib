"""One-time (re-runnable) generator for the NCA CGIoT-1:2024 control catalog.

Parses docs/reference/CGIoT-1_2024.md - a page-by-page transcription of the
source PDF (CGIoT-.pdf) that was already transcribed and fact-checked against
the PDF in an earlier session (see its own header) - into all 81 guideline
entries. This script does NOT read the PDF itself: the markdown is the
already-verified source of truth, so canonical wording here is copied
verbatim, never invented.

Output (policies/nca/catalog_1_2024.json) is a committed, human-reviewed
artifact, not something regenerated at request time. Re-run this script only
when the source markdown changes or a new framework_version is added
(alongside this file, not in place of it - see docs/nca-compliance.md).

Fields NOT present in the standard's own text (scope_type, assessment_type,
required, severity, evidence_requirements, remediation_guidance) are
IoTGuard's own methodology, authored in the CLASSIFICATION tables below -
never presented as NCA's own classification. source_page is a PDF page
*range* for guidelines that share a transcription page-marker block with
others; do not read it as exact per-guideline pagination - that precision
isn't available from the existing transcription and is not fabricated here.
"""

import json
import re
from pathlib import Path

MARKDOWN_PATH = Path(__file__).resolve().parents[2] / "docs" / "reference" / "CGIoT-1_2024.md"
OUTPUT_PATH = Path(__file__).resolve().parent / "catalog_1_2024.json"

FRAMEWORK = "NCA-CGIoT"
FRAMEWORK_VERSION = "1:2024"

DOMAIN_HEADING_RE = re.compile(r"^## (\d) — (.+)$", re.MULTILINE)
SUBDOMAIN_HEADING_RE = re.compile(r"^### (\d+-\d+) ([^\n]+)$", re.MULTILINE)
GUIDELINE_START_RE = re.compile(r"^- \*\*(\d+-\d+-\d+)\*\* (.+)$")
PAGE_MARKER_RE = re.compile(r"^<!-- =+ PDF pages? ([\d–-]+).*-->$", re.MULTILINE)

# IoTGuard's own classification - NOT part of the NCA standard's text. Domain 2
# subdomains get "device"/"automated"|"hybrid" only where a real, already-built
# SCAN_CATALOG test exists (see policies/catalog/scan_tests.py); every other
# guideline in every domain is organizational/manual by default, since a
# network or device scan cannot demonstrate policy approval, training,
# audits, or supplier/cloud contract compliance (explicit brief requirement).
DEVICE_TESTABLE_GUIDELINES: dict[str, tuple[str, str]] = {
    # guideline_id -> (scope_type, assessment_type)
    #
    # assessment_type is re-derived from the real collectors and finding
    # mappings that exist today (policies/catalog/scan_tests.py,
    # policies/nca/seed_finding_mappings.py), not assumed - several entries
    # below were caught still saying "manual" even though a real automated
    # collector had been added for them in a later session and this table
    # was never revisited (2-4-2, 2-4-6, 2-9-1, 2-13-2, 2-15-1). "hybrid"
    # means real automated evidence exists but doesn't cover every way the
    # guideline could be satisfied or violated; "automated" means the
    # automated signal alone is a defensible, complete verdict.
    "2-2-1": ("device", "hybrid"),      # access/permission restriction - partly observable, partly policy
    "2-2-2": ("device", "automated"),   # default/hard-coded creds - TEST-AUTH-DEFAULT-CREDS
    "2-4-2": ("device", "hybrid"),      # peer authentication - TEST-MQTT-OPEN's mqtt_anonymous signal (MQTT devices only)
    "2-4-3": ("device", "automated"),   # encrypt/authenticate transactions - TEST-TLS-CONFIG / TEST-NET-PKTCAPTURE
    "2-4-5": ("device", "hybrid"),      # peer authentication (TLS) - TEST-TLS-CLIENT-AUTH's client_cert_requested signal
    "2-4-6": ("device", "hybrid"),      # secure update transport - update-script-present gives partial (review_required) signal
    "2-7-2": ("device", "automated"),   # data encryption in transit - same TLS/MQTT/packet-capture signal set as 2-4-3
    "2-9-1": ("device", "hybrid"),      # vulnerability identification - firmware manifest/banner give partial (review_required) signal
    "2-9-2": ("device", "manual"),
    "2-11-1": ("device", "hybrid"),     # device/security logs - TEST-SECURITY-LOG-ENDPOINT checks conventional paths only
    "2-11-2": ("device", "hybrid"),     # diagnostic monitoring - TEST-MONITORING-ENDPOINT checks conventional paths only
    "2-13-2": ("device", "hybrid"),     # physical tamper protection - TEST-PHYSICAL-TAMPER-STATUS checks self-reported wiring only
    "2-14-1": ("device", "hybrid"),     # exposed application interface - TEST-NET-HTTP-INSPECT/TEST-ADMIN-UNAUTH give partial signal
    "2-14-2": ("device", "manual"),     # application allowlisting
    "2-15-1": ("device", "hybrid"),     # secure boot / root of trust - firmware-cert-or-key-embedded gives partial signal
    "2-15-2": ("device", "hybrid"),     # secure default config / unnecessary services - TEST-NET-PORTSCAN/TEST-MODBUS-PROBE/TEST-UPNP-PROBE
    "2-15-3": ("device", "manual"),     # end-of-life / disposal
    "3-1-1": ("device", "manual"),      # fail-safe capability
    "3-1-2": ("device", "manual"),
    "2-6-2": ("device", "hybrid"),      # data protection in transit/at rest - TEST-RTSP-PROBE/TEST-MDNS-PROBE give partial signal
    "2-6-3": ("device", "hybrid"),      # unnecessary sensitive-data collection - same RTSP/mDNS signal
}

MOBILE_GUIDELINES = {"2-5-1"}
SUPPLIER_GUIDELINES = {"4-1-1", "4-1-2", "4-1-3", "4-1-4", "4-1-5", "4-1-6"}
CLOUD_GUIDELINES = {"4-2-1", "4-2-2", "4-2-3", "4-2-4", "4-2-5"}

# Required-vs-optional and severity are likewise IoTGuard judgment calls, not
# NCA text: every guideline is treated as "required" (the standard doesn't
# mark any as optional), severity defaults to "medium" except where a
# concrete, well-known device weakness is at stake.
HIGH_SEVERITY_GUIDELINES = {
    "2-2-2", "2-4-3", "2-7-1", "2-7-2", "2-15-2",
}

# The severity tier above "high": serious enough that a high aggregate
# score alone should not read as an outright "Passed" readiness
# classification (see evaluator.py::overall_classification's
# critical_failure_rows check), but deliberately not part of
# BLOCKING_GUIDELINES below - those are severe enough to force FAILED
# regardless of score; this tier downgrades PASSED to PARTIALLY_PASSED
# instead. IoTGuard's own judgment call, same authoring convention as
# HIGH_SEVERITY_GUIDELINES/BLOCKING_GUIDELINES: unpatched known
# vulnerabilities (2-9-1/2-9-2) and a missing secure-boot/root-of-trust
# chain (2-15-1) are each, on their own, a real-world exploitation path
# that a device's other passing controls don't mitigate.
CRITICAL_SEVERITY_GUIDELINES = {
    "2-9-1",   # vulnerability identification
    "2-9-2",   # vulnerability remediation
    "2-15-1",  # secure boot / root of trust
}

# Guidelines whose FAILURE alone forces the overall device readiness
# classification to FAILED regardless of score (see
# policies/nca/evaluator.py::overall_classification and
# docs/nca-compliance.md's "blocking conditions" section) - IoTGuard's own
# judgment call about which of these represent a severe enough real-world
# exposure that a good score elsewhere shouldn't offset it, not something
# the NCA standard itself flags. Deliberately small and limited to
# guidelines with a concrete, well-known device weakness at stake (matches
# the project's own worked examples: default credentials, unencrypted
# sensitive data in transit, unnecessary/insecure exposed services).
BLOCKING_GUIDELINES = {
    "2-2-2",   # default or hard-coded credentials remain enabled
    "2-4-3",   # sensitive data transmitted without encryption/authentication
    "2-15-2",  # unnecessary/insecure exposed services (e.g. Telnet)
}

MANUFACTURER_PRINCIPLE_RE = re.compile(r"^\|\s*(\d+)\s*\|\s*(.+?)\s*\|$", re.MULTILINE)


def control_id(guideline_id: str) -> str:
    """The compliance_controls.id this guideline is stored under - shared
    with seed_finding_mappings.py so a mapping's control_id is always built
    the same way the catalog itself was, rather than a second copy of this
    format string drifting out of sync."""
    return f"{FRAMEWORK}-{FRAMEWORK_VERSION.replace(':', '_')}-{guideline_id}"


def _scope_and_assessment(guideline_id: str) -> tuple[str, str]:
    if guideline_id in DEVICE_TESTABLE_GUIDELINES:
        return DEVICE_TESTABLE_GUIDELINES[guideline_id]
    if guideline_id in MOBILE_GUIDELINES:
        return ("mobile", "manual")
    if guideline_id in SUPPLIER_GUIDELINES:
        return ("supplier", "manual")
    if guideline_id in CLOUD_GUIDELINES:
        return ("cloud", "manual")
    return ("organization", "manual")


def _severity(guideline_id: str) -> str:
    if guideline_id in CRITICAL_SEVERITY_GUIDELINES:
        return "critical"
    return "high" if guideline_id in HIGH_SEVERITY_GUIDELINES else "medium"


def _line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _page_markers(text: str) -> list[tuple[int, str]]:
    """[(line_number, page_label)] from the transcription's own
    <!-- PDF page(s) N --> / <!-- PDF pages N-M --> comments, sorted."""
    markers = [
        (_line_number(text, m.start()), m.group(1))
        for m in PAGE_MARKER_RE.finditer(text)
    ]
    markers.sort()
    return markers


def _page_for_line(markers: list[tuple[int, str]], line_no: int) -> str | None:
    label = None
    for marker_line, marker_label in markers:
        if marker_line <= line_no:
            label = marker_label
        else:
            break
    return label


def _implementation_summary(canonical_requirement: str) -> str:
    """A short, plain-language summary distinct from the canonical wording -
    stored separately per the brief, never mixed with it. Deterministic
    truncation to the requirement's own first clause (not an LLM paraphrase -
    this project's evidence/summary text is deterministic, never AI-decided)."""
    first_line = canonical_requirement.split("\n", 1)[0]
    first_clause = re.split(r"(?<=[a-z0-9)])[:.](?:\s|$)", first_line, maxsplit=1)[0]
    summary = first_clause.strip()
    if len(summary) > 220:
        summary = summary[:217].rstrip() + "..."
    return summary


def _parse_guidelines(subdomain_text: str) -> list[str]:
    """Return [canonical_requirement, ...] preserving sub-bullet continuation
    lines that belong to the same guideline (e.g. 2-2-2's password rules)."""
    lines = subdomain_text.split("\n")
    guidelines: list[tuple[str, list[str]]] = []
    for line in lines:
        match = GUIDELINE_START_RE.match(line)
        if match:
            guidelines.append((match.group(1), [match.group(2)]))
        elif guidelines and line.strip() not in ("", "---"):
            guidelines[-1][1].append(line)
    return guidelines


def build_catalog() -> list[dict]:
    text = MARKDOWN_PATH.read_text(encoding="utf-8")
    markers = _page_markers(text)
    domains = list(DOMAIN_HEADING_RE.finditer(text))
    entries: list[dict] = []

    for i, domain_match in enumerate(domains):
        domain_id = domain_match.group(1)
        domain_name = domain_match.group(2).strip()
        domain_end = domains[i + 1].start() if i + 1 < len(domains) else len(text)
        domain_text = text[domain_match.end():domain_end]
        domain_text_start = domain_match.end()

        subdomains = list(SUBDOMAIN_HEADING_RE.finditer(domain_text))
        for j, sub_match in enumerate(subdomains):
            subdomain_id = sub_match.group(1)
            # Strip a trailing "(ABBREV)" parenthetical, e.g. "... (BCM)" -
            # the brief's own 27-subdomain list names them without it.
            subdomain_name = re.sub(r"\s*\([^)]*\)\s*$", "", sub_match.group(2).strip())
            sub_end = subdomains[j + 1].start() if j + 1 < len(subdomains) else len(domain_text)
            sub_text = domain_text[sub_match.end():sub_end]
            sub_text_start_abs = domain_text_start + sub_match.end()

            for guideline_id, body_lines in _parse_guidelines(sub_text):
                canonical_requirement = "\n".join(body_lines).strip()
                # Locate this guideline's own line within the full document to
                # resolve its page marker.
                marker_line = None
                for offset, line in enumerate(sub_text.split("\n")):
                    if line.strip().startswith(f"- **{guideline_id}**"):
                        marker_line = _line_number(
                            text, sub_text_start_abs
                        ) + offset
                        break
                source_page = _page_for_line(markers, marker_line) if marker_line else None
                scope_type, assessment_type = _scope_and_assessment(guideline_id)

                entries.append({
                    "id": control_id(guideline_id),
                    "framework": FRAMEWORK,
                    "framework_version": FRAMEWORK_VERSION,
                    "domain_id": domain_id,
                    "domain_name": domain_name,
                    "subdomain_id": subdomain_id,
                    "subdomain_name": subdomain_name,
                    "guideline_id": guideline_id,
                    "canonical_requirement": canonical_requirement,
                    "implementation_summary": _implementation_summary(canonical_requirement),
                    "source_page": source_page,
                    "scope_type": scope_type,
                    "assessment_type": assessment_type,
                    "required": True,
                    "severity": _severity(guideline_id),
                    "blocking": guideline_id in BLOCKING_GUIDELINES,
                    "evidence_requirements": [],
                    "remediation_guidance": "",
                    "enabled": True,
                })
    return entries


def build_manufacturer_principles() -> list[dict]:
    """Appendix A - IoT Cybersecurity Principles for Manufactures - used by
    the finding-mapping layer for cross-references like 'Manufacturer
    Principle 5' alongside a guideline_id."""
    text = MARKDOWN_PATH.read_text(encoding="utf-8")
    appendix_start = text.index("Appendix (A)")
    appendix_end = text.index("Appendix (B)")
    appendix_text = text[appendix_start:appendix_end]
    principles = []
    for match in MANUFACTURER_PRINCIPLE_RE.finditer(appendix_text):
        number, wording = match.groups()
        if not number.isdigit():
            continue
        plain_wording = wording.replace("**", "").strip()
        principles.append({"number": int(number), "wording": plain_wording})
    return principles


def main() -> None:
    catalog = build_catalog()
    principles = build_manufacturer_principles()
    output = {
        "framework": FRAMEWORK,
        "framework_version": FRAMEWORK_VERSION,
        "source": "docs/reference/CGIoT-1_2024.md (transcribed from CGIoT-.pdf)",
        "guideline_count": len(catalog),
        "guidelines": catalog,
        "manufacturer_principles": principles,
    }
    OUTPUT_PATH.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(catalog)} guidelines and {len(principles)} manufacturer principles to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
