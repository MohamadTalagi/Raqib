from unittest.mock import MagicMock, patch

import requests

from lab.auditor.worker.scan_scripts import oui_lookup

REAL_SHAPED_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    'MA-L,286FB9,"Nokia Shanghai Bell Co., Ltd.","No.388 Ning Qiao Road,Jin Qiao Pudong Shanghai Shanghai   CN 201206 "\n'
    "MA-L,90D529,ACCTON TECHNOLOGY CORPORATION,\"No.1, Creation Road 3, Hsinchu Science Park, Hsinchu  TW 30077 \"\n"
    "MA-L,E80AB9,\"Cisco Systems, Inc\",80 West Tasman Drive San Jose CA US 95134 \n"
)


def _mock_response(text, status_ok=True):
    response = MagicMock()
    response.text = text
    response.raise_for_status.side_effect = None if status_ok else requests.HTTPError("500")
    return response


@patch("lab.auditor.worker.scan_scripts.oui_lookup.requests.get")
def test_fetch_and_cache_oui_registry_writes_the_cache_on_success(mock_get, tmp_path, monkeypatch):
    cache_path = tmp_path / "ieee-oui.csv"
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", cache_path)
    mock_get.return_value = _mock_response(REAL_SHAPED_CSV)

    assert oui_lookup.fetch_and_cache_oui_registry() is True
    assert cache_path.read_text(encoding="utf-8") == REAL_SHAPED_CSV
    # No leftover .tmp file - the atomic swap must consume it.
    assert not cache_path.with_suffix(".csv.tmp").exists()


@patch("lab.auditor.worker.scan_scripts.oui_lookup.requests.get")
def test_fetch_and_cache_oui_registry_sends_a_browser_shaped_user_agent(mock_get, tmp_path, monkeypatch):
    # A real, live-confirmed finding: the IEEE registry's front-end 418s on
    # the default `requests` User-Agent, so this must never regress to a
    # bare requests.get() with no headers.
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", tmp_path / "ieee-oui.csv")
    mock_get.return_value = _mock_response(REAL_SHAPED_CSV)

    oui_lookup.fetch_and_cache_oui_registry()

    _, kwargs = mock_get.call_args
    assert "python-requests" not in kwargs["headers"]["User-Agent"]


@patch("lab.auditor.worker.scan_scripts.oui_lookup.requests.get")
def test_fetch_and_cache_oui_registry_never_raises_on_network_failure(mock_get, tmp_path, monkeypatch):
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", tmp_path / "ieee-oui.csv")
    mock_get.side_effect = requests.ConnectionError("no route to host")

    assert oui_lookup.fetch_and_cache_oui_registry() is False


@patch("lab.auditor.worker.scan_scripts.oui_lookup.requests.get")
def test_fetch_and_cache_oui_registry_rejects_a_response_that_is_not_the_real_csv_shape(mock_get, tmp_path, monkeypatch):
    cache_path = tmp_path / "ieee-oui.csv"
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", cache_path)
    mock_get.return_value = _mock_response("<html>not the real feed</html>")

    assert oui_lookup.fetch_and_cache_oui_registry() is False
    assert not cache_path.exists()


@patch("lab.auditor.worker.scan_scripts.oui_lookup.requests.get")
def test_fetch_and_cache_oui_registry_leaves_the_prior_cache_in_place_on_failure(mock_get, tmp_path, monkeypatch):
    cache_path = tmp_path / "ieee-oui.csv"
    cache_path.write_text(REAL_SHAPED_CSV, encoding="utf-8")
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", cache_path)
    mock_get.side_effect = requests.Timeout("took too long")

    assert oui_lookup.fetch_and_cache_oui_registry() is False
    assert cache_path.read_text(encoding="utf-8") == REAL_SHAPED_CSV  # unchanged


def test_load_oui_index_builds_an_oui_keyed_dict(tmp_path, monkeypatch):
    cache_path = tmp_path / "ieee-oui.csv"
    cache_path.write_text(REAL_SHAPED_CSV, encoding="utf-8")
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", cache_path)

    index = oui_lookup.load_oui_index()

    assert index["286FB9"] == "Nokia Shanghai Bell Co., Ltd."
    assert index["E80AB9"] == "Cisco Systems, Inc"
    assert "FFFFFF" not in index


def test_load_oui_index_returns_empty_dict_when_no_cache_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", tmp_path / "does-not-exist.csv")
    assert oui_lookup.load_oui_index() == {}


def test_load_oui_index_returns_empty_dict_for_corrupt_cache(tmp_path, monkeypatch):
    cache_path = tmp_path / "ieee-oui.csv"
    cache_path.write_text("not,a,valid,header\ngarbage", encoding="utf-8")
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", cache_path)
    # A malformed-but-parseable CSV (wrong columns) yields an empty index
    # rather than raising - "Assignment"/"Organization Name" keys are
    # simply absent from every row.
    assert oui_lookup.load_oui_index() == {}


def test_lookup_vendor_resolves_a_known_oui(tmp_path, monkeypatch):
    cache_path = tmp_path / "ieee-oui.csv"
    cache_path.write_text(REAL_SHAPED_CSV, encoding="utf-8")
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", cache_path)

    assert oui_lookup.lookup_vendor("28:6F:B9:11:22:33") == "Nokia Shanghai Bell Co., Ltd."
    assert oui_lookup.lookup_vendor("28-6F-B9-11-22-33") == "Nokia Shanghai Bell Co., Ltd."


def test_lookup_vendor_returns_none_for_a_locally_administered_mac_not_in_the_registry(tmp_path, monkeypatch):
    # Docker assigns virtual, locally-administered MACs (the second bit of
    # the first octet set, e.g. 0xE6 = 0b11100110) - these correctly have no
    # IEEE registry entry. This must return None, never a fabricated guess.
    cache_path = tmp_path / "ieee-oui.csv"
    cache_path.write_text(REAL_SHAPED_CSV, encoding="utf-8")
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", cache_path)

    assert oui_lookup.lookup_vendor("E6:4D:1A:E6:45:D7") is None


def test_lookup_vendor_returns_none_when_no_cache_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_PATH", tmp_path / "does-not-exist.csv")
    assert oui_lookup.lookup_vendor("28:6F:B9:11:22:33") is None


def test_lookup_vendor_accepts_a_preloaded_index_to_avoid_rereading_the_file():
    index = {"286FB9": "Nokia Shanghai Bell Co., Ltd."}
    assert oui_lookup.lookup_vendor("28:6F:B9:11:22:33", index=index) == "Nokia Shanghai Bell Co., Ltd."
