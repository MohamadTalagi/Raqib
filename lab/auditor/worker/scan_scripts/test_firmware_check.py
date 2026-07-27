import io
import tarfile
import zipfile
from contextlib import redirect_stdout

import pytest

from lab.auditor.worker.firmware.archive_reader import open_archive
from lab.auditor.worker.firmware.generate_firmware import build_variant
from lab.auditor.worker.scan_scripts import firmware_check


def _repackage_as_zip(targz_path, zip_path):
    """Rebuild a built .tar.gz fixture as a .zip, preserving each file's name,
    bytes, and unix mode (so the executable bit survives, exercising the same
    detection path a unix-made zip would). Returns zip_path."""
    with tarfile.open(targz_path, "r:gz") as tar, zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for m in tar.getmembers():
            if not m.isfile():
                continue
            info = zipfile.ZipInfo(m.name)
            info.external_attr = (m.mode & 0o7777) << 16
            zf.writestr(info, tar.extractfile(m).read())
    return zip_path


def _variant(fmt, name, tmp_path):
    """A firmware fixture for `name`, as .tar.gz or repackaged .zip."""
    targz = build_variant(name, output_dir=tmp_path)
    if fmt == "targz":
        return targz
    return _repackage_as_zip(targz, tmp_path / f"{name}.zip")


BOTH_FORMATS = pytest.mark.parametrize("fmt", ["targz", "zip"])


def _run(check_name, archive_path):
    buf = io.StringIO()
    with open_archive(archive_path) as archive, redirect_stdout(buf):
        firmware_check.CHECKS[check_name](list(archive.iter_members()), archive_path)
    return buf.getvalue()


@BOTH_FORMATS
def test_version_check_reports_presence_and_contents(fmt, tmp_path):
    output = _run("version", _variant(fmt, "device-insecure", tmp_path))
    assert "version_file_present=True" in output
    assert "firmware_version=1.0.0-old" in output


@BOTH_FORMATS
def test_config_check_finds_the_ini_file(fmt, tmp_path):
    output = _run("config", _variant(fmt, "device-insecure", tmp_path))
    assert "config_files_present=True" in output
    assert "etc/config.ini" in output


@BOTH_FORMATS
def test_secrets_check_flags_insecure_but_not_hardened(fmt, tmp_path):
    assert "hardcoded_secret_found=True" in _run("secrets", _variant(fmt, "device-insecure", tmp_path))
    assert "hardcoded_secret_found=False" in _run("secrets", _variant(fmt, "device-hardened", tmp_path))


@BOTH_FORMATS
def test_apikey_check_flags_insecure_but_not_partial(fmt, tmp_path):
    assert "api_key_found=True" in _run("apikey", _variant(fmt, "device-insecure", tmp_path))
    assert "api_key_found=False" in _run("apikey", _variant(fmt, "device-partial", tmp_path))


def test_certkey_check_finds_nothing_in_current_fixtures(tmp_path):
    # None of the 3 synthetic fixtures embed a real cert/key today - this
    # locks in that fact so a future fixture change is noticed here too.
    path = build_variant("device-hardened", output_dir=tmp_path)
    assert "cert_or_key_present=False" in _run("certkey", path)


@BOTH_FORMATS
def test_manifest_check_reports_real_packages(fmt, tmp_path):
    output = _run("manifest", _variant(fmt, "device-insecure", tmp_path))
    assert "manifest_present=True" in output
    assert "openssl:1.0.1e" in output
    assert "busybox:1.19.4" in output


@BOTH_FORMATS
def test_updatescript_check_finds_the_script_and_its_shebang(fmt, tmp_path):
    output = _run("updatescript", _variant(fmt, "device-insecure", tmp_path))
    assert "update_script_present=True" in output
    assert "first_line=#!/bin/sh" in output


def test_main_dispatches_on_a_zip_archive(tmp_path, monkeypatch, capsys):
    # End to end through main(): the on-disk name is format-neutral
    # ({device_id}.archive) and the format is detected by content.
    firmware_dir = tmp_path / "firmware"
    firmware_dir.mkdir()
    _repackage_as_zip(
        build_variant("device-insecure", output_dir=tmp_path),
        firmware_dir / "device-insecure.archive",
    )
    monkeypatch.setattr(firmware_check, "DOCUMENT_STORE_DIR", tmp_path)
    monkeypatch.setattr("sys.argv", ["firmware_check.py", "device-insecure", "manifest"])
    firmware_check.main()
    assert "manifest_present=True" in capsys.readouterr().out


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
