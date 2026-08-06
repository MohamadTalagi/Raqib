"""Tests for TEST-DEVICE-MAC-VENDOR's collector script.

The contract under test is the stdout `field=value` format, since that is the
only coupling between this script and
scan_tests._parse_mac_vendor_observations - a silent rename on either side
would produce empty observations rather than an error.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from lab.auditor.worker.scan_scripts import mac_vendor_check


def _device_response(info: dict):
    response = MagicMock()
    response.json.return_value = info
    response.raise_for_status.side_effect = None
    return response


def _lines(capsys) -> dict:
    fields = {}
    for line in capsys.readouterr().out.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key] = value
    return fields


@patch("lab.auditor.worker.scan_scripts.mac_vendor_check.macvendors_lookup.resolve_vendor")
@patch("lab.auditor.worker.scan_scripts.mac_vendor_check.requests.get")
def test_extracts_the_mac_automatically_and_prints_the_resolved_vendor(
    mock_get, mock_resolve, capsys, monkeypatch,
):
    monkeypatch.setattr("sys.argv", ["mac_vendor_check.py", "http://device-insecure"])
    mock_get.return_value = _device_response({
        "vendor": "Hikvision", "model": "DS-2CD2143G2-I", "mac": "A4:14:37:00:11:22",
    })
    mock_resolve.return_value = {
        "oui": "A41437", "vendor": "Hangzhou Hikvision Digital Technology Co.,Ltd.",
        "source": "macvendors", "error": None,
    }

    mac_vendor_check.main()

    fields = _lines(capsys)
    assert fields["mac"] == "A4:14:37:00:11:22"
    assert fields["claimed_vendor"] == "Hikvision"
    assert fields["mac_disclosed"] == "True"
    assert fields["oui"] == "A41437"
    assert fields["oui_vendor"] == "Hangzhou Hikvision Digital Technology Co.,Ltd."
    assert fields["oui_source"] == "macvendors"
    # The MAC is read from the device, never passed in by a human.
    mock_get.assert_called_once()
    assert mock_get.call_args[0][0] == "http://device-insecure/api/device/info"
    mock_resolve.assert_called_once_with("A4:14:37:00:11:22")


@patch("lab.auditor.worker.scan_scripts.mac_vendor_check.macvendors_lookup.resolve_vendor")
@patch("lab.auditor.worker.scan_scripts.mac_vendor_check.requests.get")
def test_exits_zero_when_the_device_discloses_no_mac(mock_get, mock_resolve, capsys, monkeypatch):
    # A real, valid outcome - not an execution failure, so no lookup is
    # attempted and the run still produces recordable evidence.
    monkeypatch.setattr("sys.argv", ["mac_vendor_check.py", "http://device-x"])
    mock_get.return_value = _device_response({"vendor": "Hikvision", "model": "M"})

    mac_vendor_check.main()

    fields = _lines(capsys)
    assert fields["mac"] == ""
    assert fields["mac_disclosed"] == "False"
    mock_resolve.assert_not_called()


@patch("lab.auditor.worker.scan_scripts.mac_vendor_check.macvendors_lookup.resolve_vendor")
@patch("lab.auditor.worker.scan_scripts.mac_vendor_check.requests.get")
def test_reports_a_lookup_error_without_failing_the_scan(mock_get, mock_resolve, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["mac_vendor_check.py", "http://device-insecure"])
    mock_get.return_value = _device_response({"vendor": "Hikvision", "mac": "A4:14:37:00:11:22"})
    mock_resolve.return_value = {
        "oui": "A41437", "vendor": None, "source": None,
        "error": "macvendors.com returned HTTP 429",
    }

    mac_vendor_check.main()

    fields = _lines(capsys)
    assert fields["oui_vendor"] == ""
    assert fields["lookup_error"] == "macvendors.com returned HTTP 429"


@patch("lab.auditor.worker.scan_scripts.mac_vendor_check.requests.get")
def test_exits_nonzero_when_the_device_is_unreachable(mock_get, capsys, monkeypatch):
    # A genuine execution failure - job_runner turns the non-zero exit into
    # record-failure -> INCONCLUSIVE evidence, never a fabricated result.
    monkeypatch.setattr("sys.argv", ["mac_vendor_check.py", "http://device-insecure"])
    mock_get.side_effect = requests.ConnectionError("connection refused")

    with pytest.raises(SystemExit) as exit_info:
        mac_vendor_check.main()

    assert exit_info.value.code == 1
    assert "error=" in capsys.readouterr().out


def test_exits_nonzero_with_no_device_url(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["mac_vendor_check.py"])
    with pytest.raises(SystemExit) as exit_info:
        mac_vendor_check.main()
    assert exit_info.value.code == 1
