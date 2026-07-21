import sys
import tarfile
from pathlib import Path

import yara

RULES_PATH = Path(__file__).parent / "rules" / "iot_secrets.yar"

# Layered protection against a hostile uploaded archive (this module used to
# only ever see synthetic fixtures from generate_firmware.py - now it also
# scans arbitrary user uploads). A tar header's declared member size is
# attacker-controlled and can understate the true decompressed size (the
# classic zip-bomb technique), so both a cheap header pre-check AND a hard
# cap on the actual bytes read are needed; the running total budget stops
# opening further members entirely once exceeded, rather than skipping-and-
# continuing, since the cost being bounded is the decompression work itself.
MAX_MEMBER_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024


def scan_archive(archive_path: Path) -> list:
    rules = yara.compile(filepath=str(RULES_PATH))
    findings = []
    total_read = 0
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if member.size > MAX_MEMBER_BYTES:
                continue
            if total_read >= MAX_TOTAL_BYTES:
                break
            data = tar.extractfile(member).read(MAX_MEMBER_BYTES + 1)
            if len(data) > MAX_MEMBER_BYTES:
                continue
            total_read += len(data)
            for match in rules.match(data=data):
                findings.append({
                    "member": member.name,
                    "rule": match.rule,
                    "severity": match.meta.get("severity", "unknown"),
                })
    return findings


def main() -> None:
    target = Path(sys.argv[1])
    for finding in scan_archive(target):
        print(finding)


if __name__ == "__main__":
    main()
