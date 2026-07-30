"""Small local, offline vulnerability reference for scan-test enrichment.

Deterministic dict lookup only - no live NVD/CVE/CISA-KEV API call - matching
this project's rule that Day-2/Day-3 evidence and verdicts are reproducible
from (tool, version, command, timestamp, hash), never dependent on live
internet state or an LLM's judgment (see CLAUDE.md §9's "AI-assisted, not
AI-decided" rule).

This is deliberately NOT a comprehensive CVE database - it's an auditor-aid
table covering exactly the component/version pairs this lab's own firmware
fixtures ship (see lab/auditor/worker/firmware/generate_firmware.py), and
every CVE listed here is real and its summary has been fact-checked, not
generated. A (name, version) pair that isn't in KNOWN_COMPONENTS returns an
honest "no local reference data" result instead of a fabricated one - the
whole point of keeping this local is to never assert something we haven't
verified.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CVE:
    id: str
    cvss: float | None
    summary: str


@dataclass(frozen=True)
class ComponentAdvisory:
    outdated: bool
    eol: bool
    latest_known_version: str
    official_patch_available: bool
    patched_version: str | None
    cves: tuple[CVE, ...] = ()
    notes: tuple[str, ...] = ()


KNOWN_COMPONENTS: dict[tuple[str, str], ComponentAdvisory] = {
    ("openssl", "1.0.1e"): ComponentAdvisory(
        outdated=True,
        eol=True,
        latest_known_version="3.x (the 1.0.x branch reached end-of-life 2016-12-31)",
        official_patch_available=True,
        patched_version="1.0.1g (Heartbleed) / 1.0.1h (CCS Injection)",
        cves=(
            CVE(
                "CVE-2014-0160", 7.5,
                "\"Heartbleed\" - a missing bounds check in the TLS heartbeat "
                "extension lets a remote attacker read up to 64KB of process "
                "memory per request, including private keys, session data, "
                "and credentials.",
            ),
            CVE(
                "CVE-2014-0224", 5.0,
                "\"CCS Injection\" - a race condition in ChangeCipherSpec "
                "processing can let a man-in-the-middle force use of weak "
                "keying material, exposing traffic to decryption.",
            ),
        ),
    ),
    ("openssl", "1.1.1k"): ComponentAdvisory(
        outdated=True,
        eol=True,
        latest_known_version="3.x (the 1.1.1 branch reached end-of-life 2023-09-11)",
        official_patch_available=True,
        patched_version="3.0 or later - no further security fixes remain for 1.1.1",
        notes=(
            "No unpatched CVEs are recorded in this local reference for "
            "1.1.1k specifically, but the 1.1.1 branch as a whole is past "
            "end-of-life and receives no further security fixes - absence "
            "of a listed CVE here is not a clean bill of health.",
        ),
    ),
    ("openssl", "3.0.11"): ComponentAdvisory(
        outdated=False,
        eol=False,
        latest_known_version="3.0.x LTS (supported until 2026-09-07), or the current 3.x release",
        official_patch_available=False,
        patched_version=None,
        notes=(
            "This reference does not track individual 3.0.x point releases "
            "- confirm 3.0.11 is still the latest 3.0.x point release before "
            "treating this as current.",
        ),
    ),
    ("busybox", "1.19.4"): ComponentAdvisory(
        outdated=True,
        eol=True,
        latest_known_version="1.36.x",
        official_patch_available=True,
        patched_version="1.36.x",
        notes=(
            "Released circa 2012 - over a decade old. No specific CVE is "
            "confirmed in this local reference, but a build this old "
            "predates many since-fixed issues and should not be treated as "
            "clean by default; verify against a live CVE database.",
        ),
    ),
    ("busybox", "1.34.1"): ComponentAdvisory(
        outdated=True,
        eol=False,
        latest_known_version="1.36.x",
        official_patch_available=True,
        patched_version="1.36.x",
        notes=("Superseded by the 1.36.x series; no specific CVE confirmed in this local reference.",),
    ),
    ("busybox", "1.36.1"): ComponentAdvisory(
        outdated=False,
        eol=False,
        latest_known_version="1.36.x",
        official_patch_available=False,
        patched_version=None,
        notes=("Current 1.36.x release line as of this reference.",),
    ),
}


def lookup_component(name: str, version: str) -> dict:
    """Return an auditor-facing advisory dict for a (component, version) pair.

    Always returns the same shape whether or not the pair is known, so
    callers can merge this straight into an observations dict without a
    branch. Unknown pairs get outdated/eol/official_patch_available=None
    (meaning "not assessed here"), never a guessed True/False.
    """
    key = (name.strip().lower(), version.strip())
    advisory = KNOWN_COMPONENTS.get(key)
    if advisory is None:
        return {
            "name": name,
            "version": version,
            "outdated": None,
            "eol": None,
            "latest_known_version": None,
            "official_patch_available": None,
            "patched_version": None,
            "kev_listed_count": None,
            "cves": [],
            "notes": [
                f"No local vulnerability reference data for {name} {version} "
                "- check NVD/CISA KEV manually before treating this as clean.",
            ],
        }
    return {
        "name": name,
        "version": version,
        "outdated": advisory.outdated,
        "eol": advisory.eol,
        "latest_known_version": advisory.latest_known_version,
        "official_patch_available": advisory.official_patch_available,
        "patched_version": advisory.patched_version,
        # This static table isn't cross-referenced against CISA KEV at all
        # (unlike the Grype-backed path) - None means "not checked here",
        # never a guessed False, matching every other field's honesty rule.
        "kev_listed_count": None,
        "cves": [{"id": c.id, "cvss": c.cvss, "summary": c.summary} for c in advisory.cves],
        "notes": list(advisory.notes),
    }
