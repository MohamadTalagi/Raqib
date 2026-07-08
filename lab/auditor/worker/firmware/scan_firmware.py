import sys
import tarfile
from pathlib import Path

import yara

RULES_PATH = Path(__file__).parent / "rules" / "iot_secrets.yar"


def scan_archive(archive_path: Path) -> list:
    rules = yara.compile(filepath=str(RULES_PATH))
    findings = []
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            data = tar.extractfile(member).read()
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
