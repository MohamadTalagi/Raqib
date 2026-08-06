"""Tests for the NVD device-CVE cache module.

Mirrors test_cisa_kev.py's shape (writes cache on success / never raises on
network failure / rejects a malformed response / leaves the prior cache in
place on failure / index builds correctly / empty dict on missing-or-corrupt
cache), because nvd_lookup.py is a deliberate copy of that module's
fetch-and-cache contract.

REAL_SHAPED_NVD_RESPONSE below is trimmed from an ACTUAL live response
captured from services.nvd.nist.gov on 2026-08-06 for
`cpe:2.3:o:assaabloy:yale_conexis_l1_firmware` (totalResults=1,
CVE-2023-26941, cvssMetricV31 baseScore 6.5) - not invented from the API
docs. That matters: the metrics key is `cvssMetricV31` with the score nested
under `cvssData.baseScore`, which is easy to get subtly wrong from memory and
would silently produce `cvss: null` for every CVE.
"""

import json
from unittest.mock import MagicMock, patch

import requests

from lab.auditor.worker.scan_scripts import nvd_lookup

REAL_SHAPED_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-26941",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2023-03-27T18:15:07.550",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Weak encryption mechanisms in RFID Tags in Yale Conexis L1 v1.1.0 "
                            "allows attackers to create a cloned tag via physical proximity."
                        ),
                    },
                    {"lang": "es", "value": "Mecanismos de cifrado debiles..."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 6.5,
                                "baseSeverity": "MEDIUM",
                            },
                        },
                    ],
                },
            },
        },
    ],
}

MULTI_CVE_RESPONSE = {
    "totalResults": 3,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2020-0001",
                "descriptions": [{"lang": "en", "value": "low severity, not exploited"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.1}}]},
            },
        },
        {
            "cve": {
                "id": "CVE-2021-34991",
                "descriptions": [{"lang": "en", "value": "unauthenticated UPnP RCE"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8}}]},
            },
        },
        {
            "cve": {
                "id": "CVE-2019-0002",
                "descriptions": [{"lang": "en", "value": "high severity, not exploited"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
            },
        },
    ],
}


def _mock_response(json_body, status_ok=True):
    response = MagicMock()
    response.json.return_value = json_body
    response.raise_for_status.side_effect = None if status_ok else requests.HTTPError("500")
    return response


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_fetch_writes_the_cache_on_success(mock_get, _kev, tmp_path, monkeypatch):
    cache_path = tmp_path / "nvd-device-cves.json"
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", cache_path)
    mock_get.return_value = _mock_response(REAL_SHAPED_NVD_RESPONSE)

    assert nvd_lookup.fetch_and_cache_device_advisories(["o:assaabloy:yale_conexis_l1_firmware"]) is True

    cached = json.loads(cache_path.read_text())["advisories"]["o:assaabloy:yale_conexis_l1_firmware"]
    assert cached[0]["id"] == "CVE-2023-26941"
    assert cached[0]["cvss"] == 6.5  # cvssData.baseScore, not a guessed nesting
    assert cached[0]["summary"].startswith("Weak encryption mechanisms")  # the en description
    assert cached[0]["kev_listed"] is False
    # No leftover .tmp file - the atomic swap must consume it.
    assert not cache_path.with_suffix(".json.tmp").exists()


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index")
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_fetch_cross_references_the_local_kev_catalog(mock_get, mock_kev, tmp_path, monkeypatch):
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", tmp_path / "cache.json")
    monkeypatch.setattr(nvd_lookup, "REQUEST_INTERVAL_SECONDS", 0)
    mock_kev.return_value = {"CVE-2021-34991": {"date_added": "2022-01-10", "known_ransomware_use": "Unknown"}}
    mock_get.return_value = _mock_response(MULTI_CVE_RESPONSE)

    nvd_lookup.fetch_and_cache_device_advisories(["o:netgear:r7000_firmware"])
    cves = nvd_lookup.load_device_advisories_index()["o:netgear:r7000_firmware"]

    # KEV-listed first even though another CVE scores higher on CVSS alone -
    # actively-exploited outranks theoretically-worse, matching the ordering
    # firmware_check.py already applies to package-level CVEs.
    assert [c["id"] for c in cves] == ["CVE-2021-34991", "CVE-2019-0002", "CVE-2020-0001"]
    assert cves[0]["kev_listed"] is True
    assert cves[0]["kev_date_added"] == "2022-01-10"
    assert cves[1]["kev_listed"] is False


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_fetch_never_raises_on_network_failure(mock_get, _kev, tmp_path, monkeypatch):
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", tmp_path / "cache.json")
    mock_get.side_effect = requests.ConnectionError("no route to host")

    assert nvd_lookup.fetch_and_cache_device_advisories(["o:netgear:r7000_firmware"]) is False


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_fetch_rejects_a_response_without_the_vulnerabilities_key(mock_get, _kev, tmp_path, monkeypatch):
    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", cache_path)
    mock_get.return_value = _mock_response({"message": "NVD is undergoing maintenance"})

    assert nvd_lookup.fetch_and_cache_device_advisories(["o:netgear:r7000_firmware"]) is False
    assert not cache_path.exists()


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_fetch_leaves_the_prior_cache_in_place_when_everything_fails(mock_get, _kev, tmp_path, monkeypatch):
    cache_path = tmp_path / "cache.json"
    prior = {"advisories": {"o:netgear:r7000_firmware": [{"id": "CVE-2016-6277"}]}}
    cache_path.write_text(json.dumps(prior))
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", cache_path)
    mock_get.side_effect = requests.Timeout("took too long")

    assert nvd_lookup.fetch_and_cache_device_advisories(["o:netgear:r7000_firmware"]) is False
    assert json.loads(cache_path.read_text()) == prior  # unchanged


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_partial_success_still_writes_what_worked_but_reports_false(mock_get, _kev, tmp_path, monkeypatch):
    # A False return means "retry everything next cycle", not "the cache is
    # invalid" - job_runner deliberately doesn't touch its sentinel on False.
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", tmp_path / "cache.json")
    monkeypatch.setattr(nvd_lookup, "REQUEST_INTERVAL_SECONDS", 0)
    mock_get.side_effect = [
        _mock_response(REAL_SHAPED_NVD_RESPONSE),
        requests.ConnectionError("dropped"),
    ]

    result = nvd_lookup.fetch_and_cache_device_advisories(
        ["o:assaabloy:yale_conexis_l1_firmware", "o:netgear:r7000_firmware"],
    )

    assert result is False
    index = nvd_lookup.load_device_advisories_index()
    assert "o:assaabloy:yale_conexis_l1_firmware" in index
    assert "o:netgear:r7000_firmware" not in index


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_a_product_with_no_cves_is_cached_as_a_real_empty_result(mock_get, _kev, tmp_path, monkeypatch):
    # "checked, found nothing" must be distinguishable from "never checked" -
    # the key is present with an empty list, not absent.
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", tmp_path / "cache.json")
    mock_get.return_value = _mock_response({"totalResults": 0, "vulnerabilities": []})

    assert nvd_lookup.fetch_and_cache_device_advisories(["o:sonos:one_firmware"]) is True
    index = nvd_lookup.load_device_advisories_index()
    assert index["o:sonos:one_firmware"] == []


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_a_cve_with_no_published_score_reports_none_rather_than_zero(mock_get, _kev, tmp_path, monkeypatch):
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", tmp_path / "cache.json")
    mock_get.return_value = _mock_response({
        "vulnerabilities": [
            {"cve": {"id": "CVE-2026-9999", "descriptions": [{"lang": "en", "value": "awaiting analysis"}], "metrics": {}}},
        ],
    })

    nvd_lookup.fetch_and_cache_device_advisories(["o:netgear:r7000_firmware"])
    cve = nvd_lookup.load_device_advisories_index()["o:netgear:r7000_firmware"][0]
    assert cve["cvss"] is None  # never a guessed 0, which would read as "harmless"


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_the_query_uses_a_product_level_virtual_match_string(mock_get, _kev, tmp_path, monkeypatch):
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", tmp_path / "cache.json")
    mock_get.return_value = _mock_response(REAL_SHAPED_NVD_RESPONSE)

    nvd_lookup.fetch_and_cache_device_advisories(["o:netgear:r7000_firmware"])

    url = mock_get.call_args[0][0]
    assert url.startswith(nvd_lookup.NVD_CVE_API_URL)
    assert "virtualMatchString=" in url
    # URL-encoded "cpe:2.3:o:netgear:r7000_firmware"
    assert "cpe%3A2.3%3Ao%3Anetgear%3Ar7000_firmware" in url


@patch("lab.auditor.worker.scan_scripts.nvd_lookup.cisa_kev.load_kev_index", return_value={})
@patch("lab.auditor.worker.scan_scripts.nvd_lookup.requests.get")
def test_an_api_key_is_sent_only_when_configured(mock_get, _kev, tmp_path, monkeypatch):
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", tmp_path / "cache.json")
    mock_get.return_value = _mock_response(REAL_SHAPED_NVD_RESPONSE)

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    nvd_lookup.fetch_and_cache_device_advisories(["o:netgear:r7000_firmware"])
    assert mock_get.call_args.kwargs["headers"] == {}

    monkeypatch.setenv("NVD_API_KEY", "real-key")
    nvd_lookup.fetch_and_cache_device_advisories(["o:netgear:r7000_firmware"])
    assert mock_get.call_args.kwargs["headers"] == {"apiKey": "real-key"}


def test_load_index_returns_empty_dict_when_no_cache_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", tmp_path / "does-not-exist.json")
    assert nvd_lookup.load_device_advisories_index() == {}


def test_load_index_returns_empty_dict_for_corrupt_cache(tmp_path, monkeypatch):
    cache_path = tmp_path / "cache.json"
    cache_path.write_text("{not valid json")
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", cache_path)
    assert nvd_lookup.load_device_advisories_index() == {}


def test_load_index_returns_empty_dict_for_an_unexpected_cache_shape(tmp_path, monkeypatch):
    cache_path = tmp_path / "cache.json"
    cache_path.write_text(json.dumps({"advisories": "not a dict"}))
    monkeypatch.setattr(nvd_lookup, "NVD_CACHE_PATH", cache_path)
    assert nvd_lookup.load_device_advisories_index() == {}
