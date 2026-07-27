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
import sys
from pathlib import Path

from lab.auditor.worker.firmware.archive_reader import Member, open_archive
from lab.auditor.worker.firmware.scan_firmware import MAX_MEMBER_BYTES, scan_archive

DOCUMENT_STORE_DIR = Path(os.environ.get("DOCUMENT_STORE_DIR", "/work/document-store"))

CERT_KEY_SUFFIXES = (".pem", ".crt", ".key", ".cer")


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
    packages = []
    if present:
        try:
            manifest = json.loads(_read_member(member).decode(errors="replace"))
            packages = [f"{p.get('name', '')}:{p.get('version', '')}" for p in manifest.get("packages", [])]
        except (json.JSONDecodeError, AttributeError):
            pass
    print(f"manifest_present={present}")
    print(f"packages={','.join(packages)}")


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
