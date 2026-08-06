"""Tests for the macvendors.com client.

The behaviours worth protecting are the ones that keep an honest answer
honest: a confirmed-unregistered OUI (HTTP 404) is a real result and must not
look like a failure; a failure must not look like "no vendor"; and neither may
be re-fetched or re-guessed on the next scan. The HTTP status codes asserted
below were all observed against the real API on 2026-08-06 (200 for every one
of this lab's 8 fixture MACs, 404 for a real Docker virtual MAC, and 429 on
the second immediate request).
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from lab.auditor.worker.scan_scripts import macvendors_lookup


@pytest.fixture(autouse=True)
def _isolate_cache_and_throttle(tmp_path, monkeypatch):
    monkeypatch.setattr(macvendors_lookup, "MACVENDORS_CACHE_PATH", tmp_path / "mac-vendors.json")
    monkeypatch.setattr(macvendors_lookup, "REQUEST_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(macvendors_lookup, "_last_request_monotonic", None)
    # Default to an empty IEEE registry so each test chooses its own tier.
    monkeypatch.setattr(macvendors_lookup.oui_lookup, "lookup_vendor", lambda mac, index=None: None)


def _response(status_code, text=""):
    response = MagicMock()
    response.status_code = status_code
    response.text = text
    return response


# -- normalize_mac ----------------------------------------------------------


def test_normalize_mac_accepts_the_common_separators():
    assert macvendors_lookup.normalize_mac("A4:14:37:00:11:22") == "A41437"
    assert macvendors_lookup.normalize_mac("a4-14-37-00-11-22") == "A41437"
    assert macvendors_lookup.normalize_mac("a414.3700.1122") == "A41437"


def test_normalize_mac_rejects_junk():
    assert macvendors_lookup.normalize_mac("") is None
    assert macvendors_lookup.normalize_mac("not-a-mac") is None
    assert macvendors_lookup.normalize_mac("A4:14") is None


# -- fetch_vendor -----------------------------------------------------------


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_fetch_vendor_returns_the_vendor_on_200(mock_get):
    mock_get.return_value = _response(200, "Hangzhou Hikvision Digital Technology Co.,Ltd.\n")
    vendor, error = macvendors_lookup.fetch_vendor("A4:14:37:00:11:22")
    assert vendor == "Hangzhou Hikvision Digital Technology Co.,Ltd."
    assert error is None


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_fetch_vendor_treats_404_as_a_definite_not_registered(mock_get):
    # (None, None) - a real checked answer, NOT an error.
    mock_get.return_value = _response(404)
    vendor, error = macvendors_lookup.fetch_vendor("E6:4D:1A:E6:45:D7")
    assert vendor is None
    assert error is None


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_fetch_vendor_retries_once_on_429_then_succeeds(mock_get):
    mock_get.side_effect = [_response(429), _response(200, "NETGEAR")]
    vendor, error = macvendors_lookup.fetch_vendor("E0:46:EE:00:22:03")
    assert vendor == "NETGEAR"
    assert error is None
    assert mock_get.call_count == 2


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_fetch_vendor_gives_up_after_one_retry_rather_than_hammering(mock_get):
    mock_get.side_effect = [_response(429), _response(429)]
    vendor, error = macvendors_lookup.fetch_vendor("E0:46:EE:00:22:03")
    assert vendor is None
    assert error is not None  # an error, never a silent "no vendor"
    assert mock_get.call_count == 2


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_fetch_vendor_never_raises_on_a_network_failure(mock_get):
    mock_get.side_effect = requests.ConnectionError("no route to host")
    vendor, error = macvendors_lookup.fetch_vendor("A4:14:37:00:11:22")
    assert vendor is None
    assert "failed" in error


def test_fetch_vendor_rejects_an_unusable_mac_without_a_call():
    vendor, error = macvendors_lookup.fetch_vendor("nonsense")
    assert vendor is None
    assert "not a usable MAC" in error


# -- resolve_vendor: the three tiers ---------------------------------------


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_resolve_falls_through_to_the_live_api_and_caches_the_hit(mock_get):
    mock_get.return_value = _response(200, "Sonos, Inc.")

    first = macvendors_lookup.resolve_vendor("38:42:0B:00:22:05")
    assert first == {"oui": "38420B", "vendor": "Sonos, Inc.",
                     "source": macvendors_lookup.SOURCE_MACVENDORS, "error": None}

    # Second call is served from cache - no second network request.
    second = macvendors_lookup.resolve_vendor("38:42:0B:00:22:05")
    assert second["vendor"] == "Sonos, Inc."
    assert second["source"] == macvendors_lookup.SOURCE_CACHE
    assert mock_get.call_count == 1


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_resolve_caches_a_confirmed_404_so_it_is_never_refetched(mock_get):
    mock_get.return_value = _response(404)

    first = macvendors_lookup.resolve_vendor("E6:4D:1A:E6:45:D7")
    assert first["vendor"] is None
    assert first["error"] is None  # checked, not failed

    second = macvendors_lookup.resolve_vendor("E6:4D:1A:E6:45:D7")
    assert second["vendor"] is None
    assert second["source"] == macvendors_lookup.SOURCE_CACHE
    assert mock_get.call_count == 1


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_resolve_prefers_the_offline_ieee_registry_over_a_network_call(mock_get, monkeypatch):
    monkeypatch.setattr(
        macvendors_lookup.oui_lookup, "lookup_vendor",
        lambda mac, index=None: "Axis Communications AB",
    )

    result = macvendors_lookup.resolve_vendor("AC:CC:8E:00:11:44")

    assert result["vendor"] == "Axis Communications AB"
    assert result["source"] == macvendors_lookup.SOURCE_IEEE_REGISTRY
    mock_get.assert_not_called()


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_resolve_does_not_cache_a_failed_lookup(mock_get):
    # A transient failure must not poison the cache into a permanent
    # "unregistered" answer.
    mock_get.side_effect = requests.Timeout("slow")

    result = macvendors_lookup.resolve_vendor("A4:14:37:00:11:22")
    assert result["vendor"] is None
    assert result["error"] is not None
    assert macvendors_lookup.load_cache() == {}


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_resolve_can_be_restricted_to_offline_sources(mock_get):
    result = macvendors_lookup.resolve_vendor("A4:14:37:00:11:22", allow_network=False)

    assert result["vendor"] is None
    assert "network lookup was disabled" in result["error"]
    mock_get.assert_not_called()


def test_resolve_rejects_an_unusable_mac():
    result = macvendors_lookup.resolve_vendor("nope")
    assert result["oui"] is None
    assert "not a usable MAC" in result["error"]


def test_load_cache_returns_empty_dict_for_a_corrupt_cache(tmp_path, monkeypatch):
    cache_path = tmp_path / "mac-vendors.json"
    cache_path.write_text("{not valid json")
    monkeypatch.setattr(macvendors_lookup, "MACVENDORS_CACHE_PATH", cache_path)
    assert macvendors_lookup.load_cache() == {}


@patch("lab.auditor.worker.scan_scripts.macvendors_lookup.requests.get")
def test_an_api_key_is_sent_only_when_configured(mock_get, monkeypatch):
    mock_get.return_value = _response(200, "NETGEAR")

    monkeypatch.delenv("MACVENDORS_API_KEY", raising=False)
    macvendors_lookup.fetch_vendor("E0:46:EE:00:22:03")
    assert mock_get.call_args.kwargs["headers"] == {}

    monkeypatch.setenv("MACVENDORS_API_KEY", "real-token")
    macvendors_lookup.fetch_vendor("E0:46:EE:00:22:03")
    assert mock_get.call_args.kwargs["headers"] == {"Authorization": "Bearer real-token"}
