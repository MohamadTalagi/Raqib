import tarfile
import zipfile

import pytest

from lab.auditor.worker.firmware.generate_firmware import build_variant
from lab.auditor.worker.firmware.scan_firmware import scan_archive


def _repackage_as_zip(targz_path, zip_path):
    with tarfile.open(targz_path, "r:gz") as tar, zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for m in tar.getmembers():
            if m.isfile():
                zf.writestr(m.name, tar.extractfile(m).read())
    return zip_path


def _variant(fmt, name, tmp_path):
    targz = build_variant(name, output_dir=tmp_path)
    return targz if fmt == "targz" else _repackage_as_zip(targz, tmp_path / f"{name}.zip")


BOTH_FORMATS = pytest.mark.parametrize("fmt", ["targz", "zip"])


@BOTH_FORMATS
def test_insecure_firmware_flags_hardcoded_password_and_api_key(fmt, tmp_path):
    findings = scan_archive(_variant(fmt, "device-insecure", tmp_path))
    rules_hit = {f["rule"] for f in findings}
    assert "HardcodedPassword" in rules_hit
    assert "EmbeddedAPIKey" in rules_hit


def test_partial_firmware_flags_weak_hardcoded_password(tmp_path):
    path = build_variant("device-partial", output_dir=tmp_path)
    findings = scan_archive(path)
    rules_hit = {f["rule"] for f in findings}
    assert "HardcodedPassword" in rules_hit
    assert "EmbeddedAPIKey" not in rules_hit


@BOTH_FORMATS
def test_hardened_firmware_has_no_secret_findings(fmt, tmp_path):
    findings = scan_archive(_variant(fmt, "device-hardened", tmp_path))
    assert findings == []
