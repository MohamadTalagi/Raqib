import tarfile

from lab.auditor.worker.firmware.generate_firmware import build_variant, sha256_of


def test_firmware_build_is_byte_reproducible(tmp_path):
    path1 = build_variant("device-insecure", output_dir=tmp_path)
    hash1 = sha256_of(path1)
    path2 = build_variant("device-insecure", output_dir=tmp_path)
    hash2 = sha256_of(path2)
    assert hash1 == hash2


def test_insecure_firmware_contains_hardcoded_password(tmp_path):
    path = build_variant("device-insecure", output_dir=tmp_path)
    with tarfile.open(path, "r:gz") as tar:
        content = tar.extractfile("etc/config.ini").read().decode()
    assert "admin_pass=admin" in content


def test_hardened_firmware_has_no_hardcoded_password(tmp_path):
    path = build_variant("device-hardened", output_dir=tmp_path)
    with tarfile.open(path, "r:gz") as tar:
        content = tar.extractfile("etc/config.ini").read().decode()
    assert "admin_pass=admin" not in content
    assert "admin_pass=Ch4ng3d-Bu7-W3ak" not in content


def test_all_three_variants_have_distinct_manifests(tmp_path):
    packages_by_variant = {}
    for device_id in ("device-insecure", "device-partial", "device-hardened"):
        path = build_variant(device_id, output_dir=tmp_path)
        with tarfile.open(path, "r:gz") as tar:
            import json
            manifest = json.loads(tar.extractfile("manifest.json").read())
        packages_by_variant[device_id] = manifest["packages"]
    assert packages_by_variant["device-insecure"] != packages_by_variant["device-hardened"]
