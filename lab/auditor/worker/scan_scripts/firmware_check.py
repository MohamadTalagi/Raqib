"""Compound helper for the 7 TEST-FW-* firmware analysis tests.

Firmware tests don't target a live host:port - they inspect an uploaded
archive keyed only by device_id, at the fixed path auditor-api writes to
(document-store/firmware/{device_id}.archive, both containers already
bind-mount document-store read-write). The archive is a .tar.gz or a .zip;
archive_reader.open_archive() detects which by magic bytes and exposes a
single member interface, so nothing here cares about the format. This script
dispatches per check_name rather than forcing every check through
scan_firmware.scan_archive()'s all-rules return shape: only 3 of the 7 checks
are YARA-rule-shaped, the rest are structural (member-name lookup, JSON
parse, shebang sniff).
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from lab.auditor.worker.firmware.archive_reader import Member, open_archive
from lab.auditor.worker.firmware.scan_firmware import MAX_MEMBER_BYTES, scan_archive
from lab.auditor.worker.scan_scripts import cisa_kev
from lab.auditor.worker.scan_scripts.sbom import build_cyclonedx_sbom
from policies.catalog.pqc_crypto_reference import firmware_crypto_pqc_status

DOCUMENT_STORE_DIR = Path(os.environ.get("DOCUMENT_STORE_DIR", "/work/document-store"))

CERT_KEY_SUFFIXES = (".pem", ".crt", ".key", ".cer")

GRYPE_TIMEOUT_SECONDS = 20


def _summarize_grype_matches(raw_stdout: str) -> list[dict]:
    """Trim Grype's verbose per-match JSON (each real match carries 50+
    reference URLs) down to exactly the fields this project's advisory shape
    needs, so the collector's printed output stays a reasonable size.

    Cross-references each CVE against the locally cached CISA KEV catalog
    (cisa_kev.load_kev_index() - a fast local file read, refreshed out of
    band by job_runner.py, never a network call here) since KEV listing
    isn't a first-class field in this pinned Grype version's own JSON."""
    data = json.loads(raw_stdout)
    kev_index = cisa_kev.load_kev_index()
    summarized = []
    for match in data.get("matches", []):
        vuln = match["vulnerability"]
        artifact = match["artifact"]
        cvss_entries = vuln.get("cvss") or []
        best_cvss = max(
            (c["metrics"]["baseScore"] for c in cvss_entries if c.get("metrics", {}).get("baseScore") is not None),
            default=None,
        )
        fix = vuln.get("fix") or {}
        kev_entry = kev_index.get(vuln["id"])
        summarized.append({
            "package": artifact["name"],
            "version": artifact["version"],
            "id": vuln["id"],
            "severity": vuln.get("severity"),
            "cvss": best_cvss,
            "fix_state": fix.get("state"),
            "fix_versions": fix.get("versions", []),
            "summary": (vuln.get("description") or "")[:400],
            "kev_listed": kev_entry is not None,
            "kev_date_added": kev_entry["date_added"] if kev_entry else None,
        })
    return summarized


def _grype_db_status() -> dict | None:
    """Which vulnerability DB snapshot `_run_grype` would use right now, so a
    finding can cite it (`grype db status` has no `-o json` flag - this
    parses its plain-text output, confirmed live against the real command).
    Returns None (never raises) if Grype isn't installed or has no DB yet."""
    try:
        result = subprocess.run(
            ["grype", "db", "status"], capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    built = re.search(r"^Built:\s+(.+)$", result.stdout, re.MULTILINE)
    checksum = re.search(r"^Checksum:\s+(\S+)$", result.stdout, re.MULTILINE)
    if not built:
        return None
    return {"built_at": built.group(1).strip(), "checksum": checksum.group(1).strip() if checksum else None}


def _run_grype(packages: list[tuple[str, str]]) -> list[dict] | None:
    """Scan `packages` against Grype's local vulnerability DB, fully offline
    (no network call here - `grype db update` is a separate, scheduled
    operation). Returns None (never raises) if Grype isn't installed, its DB
    hasn't been fetched yet, or anything else goes wrong - callers fall back
    to the static reference table, exactly like an unresolved lookup today."""
    if not packages:
        return None
    sbom_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(build_cyclonedx_sbom(packages), f)
            sbom_path = f.name
        result = subprocess.run(
            ["grype", f"sbom:{sbom_path}", "-o", "json", "--add-cpes-if-none"],
            capture_output=True,
            text=True,
            timeout=GRYPE_TIMEOUT_SECONDS,
            check=False,
        )
        if result.returncode != 0:
            return None
        return _summarize_grype_matches(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError):
        return None
    finally:
        if sbom_path is not None:
            try:
                os.unlink(sbom_path)
            except OSError:
                pass


def _archive_path(device_id: str) -> Path:
    return DOCUMENT_STORE_DIR / "firmware" / f"{device_id}.archive"


def _read_member(member: Member) -> bytes:
    if member.size > MAX_MEMBER_BYTES:
        return b""
    data = member.read(MAX_MEMBER_BYTES + 1)
    return b"" if len(data) > MAX_MEMBER_BYTES else data


def check_version(members: list[Member], archive_path: Path) -> None:
    member = next((m for m in members if m.is_file and m.name == "VERSION"), None)
    print(f"version_file_present={member is not None}")
    if member is not None:
        print(f"firmware_version={_read_member(member).decode(errors='replace').strip()}")


def check_config(members: list[Member], archive_path: Path) -> None:
    names = [
        m.name for m in members
        if m.is_file and ("config" in m.name.lower() or m.name.lower().endswith((".ini", ".conf", ".cfg")))
    ]
    print(f"config_files_present={len(names) > 0}")
    print(f"config_files={','.join(names)}")


def check_secrets(members: list[Member], archive_path: Path) -> None:
    findings = scan_archive(archive_path)
    print(f"hardcoded_secret_found={any(f['rule'] == 'HardcodedPassword' for f in findings)}")


def check_apikey(members: list[Member], archive_path: Path) -> None:
    findings = scan_archive(archive_path)
    print(f"api_key_found={any(f['rule'] == 'EmbeddedAPIKey' for f in findings)}")


def check_certkey(members: list[Member], archive_path: Path) -> None:
    findings = scan_archive(archive_path)
    yara_hit = any(f["rule"] == "PrivateKeyFile" for f in findings)
    # No current synthetic fixture embeds a real cert/key, and a real one
    # might be DER-encoded (no PEM marker for YARA to match) - a plain
    # filename-suffix check catches that case too.
    suffix_hit = any(m.is_file and m.name.lower().endswith(CERT_KEY_SUFFIXES) for m in members)
    print(f"cert_or_key_present={yara_hit or suffix_hit}")


def check_manifest(members: list[Member], archive_path: Path) -> None:
    member = next((m for m in members if m.is_file and m.name == "manifest.json"), None)
    present = member is not None
    packages: list[tuple[str, str]] = []
    if present:
        try:
            manifest = json.loads(_read_member(member).decode(errors="replace"))
            packages = [(p.get("name", ""), p.get("version", "")) for p in manifest.get("packages", [])]
        except (json.JSONDecodeError, AttributeError):
            pass
    print(f"manifest_present={present}")
    print(f"packages={','.join(f'{n}:{v}' for n, v in packages)}")
    grype_matches = _run_grype(packages)
    if grype_matches is not None:
        print(f"grype_result={json.dumps(grype_matches)}")
        db_status = _grype_db_status()
        if db_status is not None:
            print(f"grype_db_built_at={db_status['built_at']}")
            if db_status["checksum"]:
                print(f"grype_db_checksum={db_status['checksum']}")


def check_pqc_crypto(members: list[Member], archive_path: Path) -> None:
    """Post-Quantum Readiness bonus stage (informational only - never
    touches policies/risk/risk_engine.py): does this device's firmware
    declare a crypto library version known to support PQC? Reuses the same
    manifest.json package list check_manifest() already parses, classified
    against pqc_crypto_reference.py's verified-not-guessed lookup table."""
    member = next((m for m in members if m.is_file and m.name == "manifest.json"), None)
    present = member is not None
    packages: list[tuple[str, str]] = []
    if present:
        try:
            manifest = json.loads(_read_member(member).decode(errors="replace"))
            packages = [(p.get("name", ""), p.get("version", "")) for p in manifest.get("packages", [])]
        except (json.JSONDecodeError, AttributeError):
            pass
    print(f"manifest_present={present}")
    results = [
        {"name": name, "version": version, "pqc_status": firmware_crypto_pqc_status(name, version)}
        for name, version in packages
    ]
    print(f"pqc_results={json.dumps(results)}")


def check_updatescript(members: list[Member], archive_path: Path) -> None:
    # Prefer the well-known name, then any executable-bit file. A zip made on
    # Windows carries no unix mode (mode == 0), so the name match is what
    # actually fires there - the exec-bit path only helps tar/unix-made zips.
    member = next(
        (m for m in members if m.is_file and (m.name == "update.sh" or (m.mode & 0o111 and m.name != "VERSION"))),
        None,
    )
    print(f"update_script_present={member is not None}")
    if member is not None:
        first_line = _read_member(member).decode(errors="replace").splitlines()[:1]
        print(f"first_line={first_line[0] if first_line else ''}")


CHECKS = {
    "version": check_version,
    "config": check_config,
    "secrets": check_secrets,
    "apikey": check_apikey,
    "certkey": check_certkey,
    "manifest": check_manifest,
    "updatescript": check_updatescript,
    "pqc_crypto": check_pqc_crypto,
}


def main() -> None:
    device_id, check_name = sys.argv[1], sys.argv[2]
    archive_path = _archive_path(device_id)
    if not archive_path.exists():
        print("error=firmware archive not found")
        return

    with open_archive(archive_path) as archive:
        members = list(archive.iter_members())
        CHECKS[check_name](members, archive_path)


if __name__ == "__main__":
    main()
