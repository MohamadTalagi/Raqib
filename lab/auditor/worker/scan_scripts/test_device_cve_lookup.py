"""Tests for TEST-DEVICE-CVE-LOOKUP's collector script.

The contract under test is the stdout `field=value` format, because that is
what scan_tests._parse_device_cve_lookup_observations reads back - the two
sides are only coupled through these lines, so a silent rename on either side
would produce empty observations rather than an error. Each test therefore
asserts the printed lines, and the parser's own tests
(policies/catalog/test_scan_tests.py) assert the other half.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from lab.auditor.worker.scan_scripts import device_cve_lookup


def _device_response(device: dict):
    response = MagicMock()
    response.json.return_value = {"device": device}
    response.raise_for_status.side_effect = None
    return response


def _lines(capsys) -> dict:
    out = capsys.readouterr().out
    fields = {}
    for line in out.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key] = value
    return fields


@patch("lab.auditor.worker.scan_scripts.device_cve_lookup.nvd_lookup.load_device_advisories_index")
@patch("lab.auditor.worker.scan_scripts.device_cve_lookup.requests.get")
def test_prints_cves_for_a_mapped_product(mock_get, mock_index, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["device_cve_lookup.py", "device-router-gw"])
    mock_get.return_value = _device_response({
        "vendor": "Netgear", "model": "R7000", "firmware_version": "V1.0.11.132_10.2.132",
    })
    cves = [{"id": "CVE-2016-6277", "cvss": 8.8, "summary": "CSRF", "kev_listed": False, "kev_date_added": None}]
    mock_index.return_value = {"o:netgear:r7000_firmware": cves}

    device_cve_lookup.main()

    fields = _lines(capsys)
    assert fields["vendor"] == "Netgear"
    assert fields["model"] == "R7000"
    assert fields["firmware_version"] == "V1.0.11.132_10.2.132"
    assert fields["cpe_matched"] == "True"
    assert fields["cpe"] == "o:netgear:r7000_firmware"
    assert fields["index_available"] == "True"
    assert json.loads(fields["device_cves"]) == cves


@patch("lab.auditor.worker.scan_scripts.device_cve_lookup.nvd_lookup.load_device_advisories_index")
@patch("lab.auditor.worker.scan_scripts.device_cve_lookup.requests.get")
def test_reports_an_unmapped_product_without_consulting_the_cache(mock_get, mock_index, capsys, monkeypatch):
    # device-nvr's real case - Dahua NVR4108-8P has no NVD CPE at all.
    monkeypatch.setattr("sys.argv", ["device_cve_lookup.py", "device-nvr"])
    mock_get.return_value = _device_response({
        "vendor": "Dahua", "model": "NVR4108-8P", "firmware_version": "3.218.0000019.0",
    })

    device_cve_lookup.main()

    fields = _lines(capsys)
    assert fields["cpe_matched"] == "False"
    assert fields["cpe"] == ""
    assert "device_cves" not in fields
    mock_index.assert_not_called()


@patch("lab.auditor.worker.scan_scripts.device_cve_lookup.nvd_lookup.load_device_advisories_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.device_cve_lookup.requests.get")
def test_distinguishes_an_unpopulated_cache_from_zero_cves(mock_get, _index, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["device_cve_lookup.py", "device-router-gw"])
    mock_get.return_value = _device_response({"vendor": "Netgear", "model": "R7000", "firmware_version": "1.0"})

    device_cve_lookup.main()

    fields = _lines(capsys)
    assert fields["cpe_matched"] == "True"
    assert fields["index_available"] == "False"  # cache empty, NOT "no CVEs exist"
    assert json.loads(fields["device_cves"]) == []


@patch("lab.auditor.worker.scan_scripts.device_cve_lookup.requests.get")
def test_reports_an_unidentified_device_without_failing(mock_get, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["device_cve_lookup.py", "device-new"])
    mock_get.return_value = _device_response({"vendor": None, "model": None, "firmware_version": None})

    device_cve_lookup.main()

    fields = _lines(capsys)
    assert fields["vendor"] == ""
    assert fields["cpe_matched"] == "False"


@patch("lab.auditor.worker.scan_scripts.device_cve_lookup.requests.get")
def test_exits_nonzero_when_the_device_record_cannot_be_read(mock_get, capsys, monkeypatch):
    # A real execution failure - job_runner turns the non-zero exit into
    # record-failure -> INCONCLUSIVE evidence, never a fabricated "no CVEs".
    monkeypatch.setattr("sys.argv", ["device_cve_lookup.py", "device-router-gw"])
    mock_get.side_effect = requests.ConnectionError("auditor-api unreachable")

    with pytest.raises(SystemExit) as exit_info:
        device_cve_lookup.main()

    assert exit_info.value.code == 1
    assert "error=" in capsys.readouterr().out


def test_exits_nonzero_with_no_device_id(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["device_cve_lookup.py"])
    with pytest.raises(SystemExit) as exit_info:
        device_cve_lookup.main()
    assert exit_info.value.code == 1
