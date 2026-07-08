from lab.auditor.worker.firmware.generate_firmware import build_variant
from lab.auditor.worker.firmware.scan_firmware import scan_archive


def test_insecure_firmware_flags_hardcoded_password_and_api_key(tmp_path):
    path = build_variant("device-insecure", output_dir=tmp_path)
    findings = scan_archive(path)
    rules_hit = {f["rule"] for f in findings}
    assert "HardcodedPassword" in rules_hit
    assert "EmbeddedAPIKey" in rules_hit


def test_partial_firmware_flags_weak_hardcoded_password(tmp_path):
    path = build_variant("device-partial", output_dir=tmp_path)
    findings = scan_archive(path)
    rules_hit = {f["rule"] for f in findings}
    assert "HardcodedPassword" in rules_hit
    assert "EmbeddedAPIKey" not in rules_hit


def test_hardened_firmware_has_no_secret_findings(tmp_path):
    path = build_variant("device-hardened", output_dir=tmp_path)
    findings = scan_archive(path)
    assert findings == []
