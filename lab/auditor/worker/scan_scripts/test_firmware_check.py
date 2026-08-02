import io
import json
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
def test_manifest_check_reports_real_packages(fmt, tmp_path, monkeypatch):
    # Explicit "Grype unavailable" so this doesn't silently depend on whether
    # the host running the test happens to have the grype binary installed.
    monkeypatch.setattr(firmware_check, "_run_grype", lambda packages: None)
    output = _run("manifest", _variant(fmt, "device-insecure", tmp_path))
    assert "manifest_present=True" in output
    assert "openssl:1.0.1e" in output
    assert "busybox:1.19.4" in output
    assert "grype_result=" not in output


@BOTH_FORMATS
def test_pqc_crypto_check_flags_the_outdated_openssl_and_leaves_busybox_unknown(fmt, tmp_path):
    output = _run("pqc_crypto", _variant(fmt, "device-insecure", tmp_path))
    assert "manifest_present=True" in output
    line = next(l for l in output.splitlines() if l.startswith("pqc_results="))
    results = {r["name"]: r["pqc_status"] for r in json.loads(line[len("pqc_results="):])}
    assert results["openssl"] == "fail"  # 1.0.1e predates PQC support entirely
    assert results["busybox"] == "unknown"  # not a recognized crypto library


def test_manifest_check_includes_grype_result_when_available(tmp_path, monkeypatch):
    canned = [{
        "package": "openssl", "version": "1.0.1e", "id": "CVE-2014-0160",
        "severity": "High", "cvss": 7.5, "fix_state": "fixed",
        "fix_versions": ["1.0.1g"], "summary": "Heartbleed",
    }]
    monkeypatch.setattr(firmware_check, "_run_grype", lambda packages: canned)
    monkeypatch.setattr(firmware_check, "_grype_db_status", lambda: {"built_at": "2026-03-09 00:31:20 +0000 UTC", "checksum": "sha256:abc123"})
    output = _run("manifest", _variant("targz", "device-insecure", tmp_path))
    assert "grype_result=" in output
    line = next(l for l in output.splitlines() if l.startswith("grype_result="))
    assert json.loads(line[len("grype_result="):]) == canned
    assert "grype_db_built_at=2026-03-09 00:31:20 +0000 UTC" in output
    assert "grype_db_checksum=sha256:abc123" in output


def test_manifest_check_omits_db_status_lines_when_grype_did_not_run(tmp_path, monkeypatch):
    monkeypatch.setattr(firmware_check, "_run_grype", lambda packages: None)
    output = _run("manifest", _variant("targz", "device-insecure", tmp_path))
    assert "grype_db_built_at=" not in output
    assert "grype_db_checksum=" not in output


def test_grype_db_status_parses_real_output_shape(monkeypatch):
    # Exact shape of `grype db status`'s real plain-text output (it has no
    # -o json flag, confirmed live) - captured from a real refreshed DB.
    real_output = (
        "Location:  /root/.cache/grype/db/5\n"
        "Built:     2026-03-09 00:31:20 +0000 UTC\n"
        "Schema:    5\n"
        "Checksum:  sha256:a65e27aecbbb2cd6671f5da84c16db7e9c60f0114075e6ae9bcc71f466460a0c\n"
        "Status:    valid\n"
    )

    class _FakeResult:
        returncode = 0
        stdout = real_output

    monkeypatch.setattr(firmware_check.subprocess, "run", lambda *a, **k: _FakeResult())
    status = firmware_check._grype_db_status()
    assert status["built_at"] == "2026-03-09 00:31:20 +0000 UTC"
    assert status["checksum"] == "sha256:a65e27aecbbb2cd6671f5da84c16db7e9c60f0114075e6ae9bcc71f466460a0c"


def test_grype_db_status_returns_none_when_command_fails(monkeypatch):
    def _raise(*args, **kwargs):
        raise FileNotFoundError("grype not on PATH")
    monkeypatch.setattr(firmware_check.subprocess, "run", _raise)
    assert firmware_check._grype_db_status() is None


def test_run_grype_returns_none_when_binary_is_missing(monkeypatch):
    def _raise(*args, **kwargs):
        raise FileNotFoundError("grype not on PATH")
    monkeypatch.setattr(firmware_check.subprocess, "run", _raise)
    assert firmware_check._run_grype([("openssl", "1.0.1e")]) is None


def test_run_grype_returns_none_for_empty_package_list():
    assert firmware_check._run_grype([]) is None


def test_summarize_grype_matches_extracts_expected_fields(monkeypatch):
    monkeypatch.setattr(firmware_check.cisa_kev, "load_kev_index", lambda: {})
    raw = json.dumps({
        "matches": [{
            "vulnerability": {
                "id": "CVE-2014-0160",
                "severity": "High",
                "cvss": [{"metrics": {"baseScore": 5.0}}, {"metrics": {"baseScore": 7.5}}],
                "fix": {"state": "fixed", "versions": ["1.0.1g"]},
                "description": "Heartbleed" * 100,
            },
            "artifact": {"name": "openssl", "version": "1.0.1e"},
        }],
    })
    [summary] = firmware_check._summarize_grype_matches(raw)
    assert summary["package"] == "openssl"
    assert summary["cvss"] == 7.5
    assert summary["fix_state"] == "fixed"
    assert summary["fix_versions"] == ["1.0.1g"]
    assert len(summary["summary"]) <= 400
    assert summary["kev_listed"] is False
    assert summary["kev_date_added"] is None


def test_summarize_grype_matches_flags_kev_listed_cves(monkeypatch):
    # CVE-2014-0160 (Heartbleed) is a real CISA KEV entry, confirmed live
    # against the real feed - used here as a realistic fixture, not fetched.
    monkeypatch.setattr(
        firmware_check.cisa_kev, "load_kev_index",
        lambda: {"CVE-2014-0160": {"date_added": "2022-03-25", "known_ransomware_use": "Unknown"}},
    )
    raw = json.dumps({
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2014-0160", "severity": "High",
                    "cvss": [{"metrics": {"baseScore": 7.5}}],
                    "fix": {"state": "fixed", "versions": ["1.0.1g"]}, "description": "Heartbleed",
                },
                "artifact": {"name": "openssl", "version": "1.0.1e"},
            },
            {
                "vulnerability": {
                    "id": "CVE-2016-6304", "severity": "High",
                    "cvss": [{"metrics": {"baseScore": 7.5}}],
                    "fix": {"state": "unknown", "versions": []}, "description": "Not KEV-listed",
                },
                "artifact": {"name": "openssl", "version": "1.0.1e"},
            },
        ],
    })
    heartbleed, other = firmware_check._summarize_grype_matches(raw)
    assert heartbleed["kev_listed"] is True
    assert heartbleed["kev_date_added"] == "2022-03-25"
    assert other["kev_listed"] is False
    assert other["kev_date_added"] is None


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
