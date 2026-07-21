import io
import tarfile
from contextlib import redirect_stdout

from lab.auditor.worker.firmware.generate_firmware import build_variant
from lab.auditor.worker.scan_scripts import firmware_check


def _run(check_name: str, archive_path):
    buf = io.StringIO()
    with tarfile.open(archive_path, "r:gz") as tar, redirect_stdout(buf):
        firmware_check.CHECKS[check_name](tar, archive_path)
    return buf.getvalue()


def test_version_check_reports_presence_and_contents(tmp_path):
    path = build_variant("device-insecure", output_dir=tmp_path)
    output = _run("version", path)
    assert "version_file_present=True" in output
    assert "firmware_version=1.0.0-old" in output


def test_config_check_finds_the_ini_file(tmp_path):
    path = build_variant("device-insecure", output_dir=tmp_path)
    output = _run("config", path)
    assert "config_files_present=True" in output
    assert "etc/config.ini" in output


def test_secrets_check_flags_insecure_but_not_hardened(tmp_path):
    insecure = build_variant("device-insecure", output_dir=tmp_path)
    hardened = build_variant("device-hardened", output_dir=tmp_path)
    assert "hardcoded_secret_found=True" in _run("secrets", insecure)
    assert "hardcoded_secret_found=False" in _run("secrets", hardened)


def test_apikey_check_flags_insecure_but_not_partial(tmp_path):
    insecure = build_variant("device-insecure", output_dir=tmp_path)
    partial = build_variant("device-partial", output_dir=tmp_path)
    assert "api_key_found=True" in _run("apikey", insecure)
    assert "api_key_found=False" in _run("apikey", partial)


def test_certkey_check_finds_nothing_in_current_fixtures(tmp_path):
    # None of the 3 synthetic fixtures embed a real cert/key today - this
    # locks in that fact so a future fixture change is noticed here too.
    path = build_variant("device-hardened", output_dir=tmp_path)
    assert "cert_or_key_present=False" in _run("certkey", path)


def test_manifest_check_reports_real_packages(tmp_path):
    path = build_variant("device-insecure", output_dir=tmp_path)
    output = _run("manifest", path)
    assert "manifest_present=True" in output
    assert "openssl:1.0.1e" in output
    assert "busybox:1.19.4" in output


def test_updatescript_check_finds_the_script_and_its_shebang(tmp_path):
    path = build_variant("device-insecure", output_dir=tmp_path)
    output = _run("updatescript", path)
    assert "update_script_present=True" in output
    assert "first_line=#!/bin/sh" in output


def test_main_reports_a_clear_error_when_archive_is_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    monkeypatch.setattr(firmware_check, "DOCUMENT_STORE_DIR", tmp_path)
    monkeypatch.setattr("sys.argv", ["firmware_check.py", "device-does-not-exist", "version"])
    firmware_check.main()
    assert "error=firmware archive not found" in capsys.readouterr().out


def test_size_cap_skips_an_oversized_member(tmp_path):
    # A member declaring a size over MAX_MEMBER_BYTES must be skipped rather
    # than fully read - simulates a hostile upload rather than the trusted
    # synthetic fixtures.
    archive_path = tmp_path / "camera-fw-oversized.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="VERSION")
        payload = b"1.0.0\n" * (firmware_check.MAX_MEMBER_BYTES // 4)
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    output = _run("version", archive_path)
    assert "version_file_present=True" in output
    assert "firmware_version=" in output
    # The member exceeded the cap, so its content must not have been read.
    assert output.strip() == "version_file_present=True\nfirmware_version="
