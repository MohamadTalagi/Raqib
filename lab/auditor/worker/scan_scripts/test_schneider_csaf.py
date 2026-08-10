"""Tests for the Schneider Electric CSAF advisory cache.

REAL_ADVISORY below is the genuine structure of ICSA-18-240-02, fetched live
from CISA's cisagov/CSAF mirror on 2026-08-10 - not invented from the CSAF
spec. The nesting depth and the fact that the range lives under "name" as an
expression string rather than in fielded keys are both easy to get wrong from
memory, and either mistake would silently yield an empty mapping.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from lab.auditor.worker.scan_scripts import schneider_csaf

REAL_ADVISORY = {
    "document": {"title": "Schneider Electric Modicon M221"},
    "product_tree": {"branches": [{"branches": [{"branches": [{
        "category": "product_version_range",
        "name": "<1.6.2.0",
        "product": {
            "name": "Modicon M221: all references and versions prior to firmware v1.6.2.0",
            "product_id": "CSAFPID-0001",
        },
    }], "category": "product_name", "name": "Modicon M221"}]}]},
    "vulnerabilities": [{
        "cve": "CVE-2018-7789",
        "product_status": {"known_affected": ["CSAFPID-0001"]},
    }],
}


@pytest.fixture(autouse=True)
def _isolate_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(schneider_csaf, "SCHNEIDER_CSAF_CACHE_PATH", tmp_path / "schneider-csaf.json")


def _response(body):
    r = MagicMock()
    r.json.return_value = body
    r.raise_for_status.side_effect = None
    return r


# -- URL derivation ---------------------------------------------------------


def test_advisory_url_derives_the_year_from_the_id():
    assert schneider_csaf.advisory_json_url("ICSA-18-240-02") == (
        "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"
        "2018/icsa-18-240-02.json"
    )
    assert "/2024/" in schneider_csaf.advisory_json_url("ICSA-24-338-01")


def test_advisory_url_refuses_an_unrecognized_id_shape():
    # A wrong URL 404s loudly, but a PLAUSIBLE wrong URL can return a real
    # advisory for a different product - so anything unexpected returns None
    # rather than being guessed at.
    assert schneider_csaf.advisory_json_url("SEVD-2024-345-03") is None
    assert schneider_csaf.advisory_json_url("") is None
    assert schneider_csaf.advisory_json_url(None) is None


# -- fetch/cache ------------------------------------------------------------


@patch("lab.auditor.worker.scan_scripts.schneider_csaf.requests.get")
def test_fetch_caches_the_real_advisory_range(mock_get):
    mock_get.return_value = _response(REAL_ADVISORY)

    assert schneider_csaf.fetch_and_cache_schneider_csaf() is True

    ranges = schneider_csaf.load_schneider_csaf_index()["cve_version_ranges"]
    assert ranges["CVE-2018-7789"]["end_excluding"] == "1.6.2.0"
    assert not schneider_csaf.SCHNEIDER_CSAF_CACHE_PATH.with_suffix(".json.tmp").exists()


@patch("lab.auditor.worker.scan_scripts.schneider_csaf.requests.get")
def test_fetch_never_raises_on_a_network_failure(mock_get):
    mock_get.side_effect = requests.ConnectionError("no route")
    assert schneider_csaf.fetch_and_cache_schneider_csaf() is False


@patch("lab.auditor.worker.scan_scripts.schneider_csaf.requests.get")
def test_fetch_leaves_a_prior_cache_intact_when_everything_fails(mock_get):
    prior = {"cve_version_ranges": {"CVE-2018-7789": {"end_excluding": "1.6.2.0"}}}
    schneider_csaf.SCHNEIDER_CSAF_CACHE_PATH.write_text(json.dumps(prior))
    mock_get.side_effect = requests.Timeout("slow")

    assert schneider_csaf.fetch_and_cache_schneider_csaf() is False
    assert json.loads(schneider_csaf.SCHNEIDER_CSAF_CACHE_PATH.read_text()) == prior


@patch("lab.auditor.worker.scan_scripts.schneider_csaf.requests.get")
def test_fetch_reports_false_when_an_advisory_parses_to_nothing(mock_get):
    # Fetched fine but said nothing usable - a real outcome, but it must not
    # look like success, or the sentinel would suppress retries for a week.
    mock_get.return_value = _response({"product_tree": {}, "vulnerabilities": []})
    assert schneider_csaf.fetch_and_cache_schneider_csaf() is False


# -- load -------------------------------------------------------------------


def test_load_returns_an_empty_mapping_when_no_cache_exists():
    assert schneider_csaf.load_schneider_csaf_index() == {"cve_version_ranges": {}}


def test_load_returns_an_empty_mapping_for_a_corrupt_cache():
    schneider_csaf.SCHNEIDER_CSAF_CACHE_PATH.write_text("{not json")
    assert schneider_csaf.load_schneider_csaf_index() == {"cve_version_ranges": {}}


def test_load_returns_an_empty_mapping_for_an_unexpected_shape():
    schneider_csaf.SCHNEIDER_CSAF_CACHE_PATH.write_text(json.dumps({"cve_version_ranges": "nope"}))
    assert schneider_csaf.load_schneider_csaf_index() == {"cve_version_ranges": {}}


def test_the_advisory_table_holds_only_individually_verified_ids():
    # Guessing an ID is actively dangerous: two plausible guesses tried during
    # implementation resolved to unrelated products. This pins the table to
    # what was actually confirmed.
    assert schneider_csaf.SCHNEIDER_M221_CSAF_ADVISORY_IDS == ["ICSA-18-240-02"]
    assert schneider_csaf.SCHNEIDER_M221_CPE_PREFIX == "o:schneider-electric:modicon_m221_firmware"
