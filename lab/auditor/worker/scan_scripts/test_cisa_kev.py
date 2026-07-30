import json
from unittest.mock import MagicMock, patch

import requests

from lab.auditor.worker.scan_scripts import cisa_kev

REAL_SHAPED_FEED = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.07.29",
    "dateReleased": "2026-07-29T00:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2014-0160",
            "vendorProject": "OpenSSL",
            "product": "OpenSSL",
            "vulnerabilityName": "OpenSSL Heartbleed",
            "dateAdded": "2022-03-25",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "CVE-2026-20316",
            "vendorProject": "Cisco",
            "product": "Secure Firewall Management Center",
            "vulnerabilityName": "Hard-coded Password Vulnerability",
            "dateAdded": "2026-07-29",
            "knownRansomwareCampaignUse": "Known",
        },
    ],
}


def _mock_response(json_body, status_ok=True):
    response = MagicMock()
    response.json.return_value = json_body
    response.raise_for_status.side_effect = None if status_ok else requests.HTTPError("500")
    return response


@patch("lab.auditor.worker.scan_scripts.cisa_kev.requests.get")
def test_fetch_and_cache_kev_feed_writes_the_cache_on_success(mock_get, tmp_path, monkeypatch):
    cache_path = tmp_path / "cisa-kev.json"
    monkeypatch.setattr(cisa_kev, "KEV_CACHE_PATH", cache_path)
    mock_get.return_value = _mock_response(REAL_SHAPED_FEED)

    assert cisa_kev.fetch_and_cache_kev_feed() is True
    assert json.loads(cache_path.read_text()) == REAL_SHAPED_FEED
    # No leftover .tmp file - the atomic swap must consume it.
    assert not cache_path.with_suffix(".json.tmp").exists()


@patch("lab.auditor.worker.scan_scripts.cisa_kev.requests.get")
def test_fetch_and_cache_kev_feed_never_raises_on_network_failure(mock_get, tmp_path, monkeypatch):
    monkeypatch.setattr(cisa_kev, "KEV_CACHE_PATH", tmp_path / "cisa-kev.json")
    mock_get.side_effect = requests.ConnectionError("no route to host")

    assert cisa_kev.fetch_and_cache_kev_feed() is False


@patch("lab.auditor.worker.scan_scripts.cisa_kev.requests.get")
def test_fetch_and_cache_kev_feed_rejects_a_response_with_no_vulnerabilities_key(mock_get, tmp_path, monkeypatch):
    cache_path = tmp_path / "cisa-kev.json"
    monkeypatch.setattr(cisa_kev, "KEV_CACHE_PATH", cache_path)
    mock_get.return_value = _mock_response({"error": "not the real feed shape"})

    assert cisa_kev.fetch_and_cache_kev_feed() is False
    assert not cache_path.exists()


@patch("lab.auditor.worker.scan_scripts.cisa_kev.requests.get")
def test_fetch_and_cache_kev_feed_leaves_the_prior_cache_in_place_on_failure(mock_get, tmp_path, monkeypatch):
    cache_path = tmp_path / "cisa-kev.json"
    cache_path.write_text(json.dumps(REAL_SHAPED_FEED))
    monkeypatch.setattr(cisa_kev, "KEV_CACHE_PATH", cache_path)
    mock_get.side_effect = requests.Timeout("took too long")

    assert cisa_kev.fetch_and_cache_kev_feed() is False
    assert json.loads(cache_path.read_text()) == REAL_SHAPED_FEED  # unchanged


def test_load_kev_index_builds_a_cve_id_keyed_dict(tmp_path, monkeypatch):
    cache_path = tmp_path / "cisa-kev.json"
    cache_path.write_text(json.dumps(REAL_SHAPED_FEED))
    monkeypatch.setattr(cisa_kev, "KEV_CACHE_PATH", cache_path)

    index = cisa_kev.load_kev_index()

    assert index["CVE-2014-0160"] == {"date_added": "2022-03-25", "known_ransomware_use": "Unknown"}
    assert index["CVE-2026-20316"]["known_ransomware_use"] == "Known"
    assert "CVE-9999-0000" not in index


def test_load_kev_index_returns_empty_dict_when_no_cache_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(cisa_kev, "KEV_CACHE_PATH", tmp_path / "does-not-exist.json")
    assert cisa_kev.load_kev_index() == {}


def test_load_kev_index_returns_empty_dict_for_corrupt_cache(tmp_path, monkeypatch):
    cache_path = tmp_path / "cisa-kev.json"
    cache_path.write_text("{not valid json")
    monkeypatch.setattr(cisa_kev, "KEV_CACHE_PATH", cache_path)
    assert cisa_kev.load_kev_index() == {}
