"""Tests for the firmware version comparator.

Every fixture here is REAL data, not synthetic: the firmware strings are read
from this lab's own lab/devices/*/app/config.py and profile env files, the NVD
shapes were fetched live from services.nvd.nist.gov on 2026-08-10, and the
CSAF shape from CISA's cisagov/CSAF mirror. That matters most for
parse_version - an earlier draft of the regex passed every synthetic case and
still returned None for Axis's real "AXIS OS 11.11.100".
"""

import pytest

from policies.catalog import firmware_version_compare as fvc

# The seven real self-reported firmware strings in this lab.
REAL_FIRMWARE_STRINGS = {
    "device-router-gw": "V1.0.11.132_10.2.132",
    "device-plc-gateway": "SV3.8.1",
    "device-insecure": "V5.3.0 build 160530",
    "device-partial": "V5.5.0 build 190723",
    "device-hardened": "AXIS OS 11.11.100",
    "device-smartlock": "1.4.2",
    "device-speaker": "15.9",
    "device-nvr": "3.218.0000019.0",
}


# -- parse_version ----------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("V1.0.11.132_10.2.132", (1, 0, 11, 132)),   # vendor prefix + underscore suffix
        ("SV3.8.1", (3, 8, 1)),                       # two-letter prefix
        ("V5.3.0 build 160530", (5, 3, 0)),           # trailing " build NNNNNN"
        ("V5.5.0 build 190723", (5, 5, 0)),
        ("AXIS OS 11.11.100", (11, 11, 100)),         # prefix WITH SPACES - regression
        ("1.4.2", (1, 4, 2)),                          # already clean
        ("15.9", (15, 9)),
        ("3.218.0000019.0", (3, 218, 19, 0)),          # leading zeros
    ],
)
def test_parse_version_handles_every_real_fixture_string(raw, expected):
    assert fvc.parse_version(raw) == expected


def test_parse_version_covers_the_whole_fleet_without_crashing():
    for device_id, raw in REAL_FIRMWARE_STRINGS.items():
        assert fvc.parse_version(raw) is not None, device_id


def test_parse_version_returns_none_rather_than_guessing():
    assert fvc.parse_version(None) is None
    assert fvc.parse_version("") is None
    assert fvc.parse_version("unknown") is None
    # A bare build number with no dot carries no reliable ordering.
    assert fvc.parse_version("210628") is None


def test_parse_version_reads_a_trailing_revision_letter_as_a_component():
    assert fvc.parse_version("1.2.3a") == (1, 2, 3, 1)
    assert fvc.parse_version("1.2.3b") == (1, 2, 3, 2)


# -- NVD extraction ---------------------------------------------------------

NETGEAR_CPE = "o:netgear:r7000_firmware"


def _nvd_item(cpe_matches):
    return {"cve": {"configurations": [{"nodes": [{"cpeMatch": cpe_matches}]}]}}


def test_extract_nvd_range_reads_a_real_bounded_shape():
    # The real shape of CVE-2021-34991, fetched live.
    item = _nvd_item([{
        "vulnerable": True,
        "criteria": "cpe:2.3:o:netgear:r7000_firmware:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "1.0.11.128",
    }])
    assert fvc.extract_nvd_version_range(item, NETGEAR_CPE) == {
        "start_including": None, "start_excluding": None,
        "end_including": None, "end_excluding": "1.0.11.128", "unbounded": False,
    }


def test_extract_nvd_range_marks_a_real_unbounded_cve_as_unbounded_not_missing():
    # CVE-2021-36260 (Hikvision) really has no version keys at all. That is a
    # definite "every version is affected", never "we don't know".
    item = _nvd_item([{
        "vulnerable": True,
        "criteria": "cpe:2.3:o:hikvision:ds-2cd2143g2-i\\(s\\)_firmware:-:*:*:*:*:*:*:*",
    }])
    result = fvc.extract_nvd_version_range(item, "o:hikvision:ds-2cd2143g2-i\\(s\\)_firmware")
    assert result["unbounded"] is True
    assert result is not None


def test_extract_nvd_range_ignores_other_products_in_the_same_record():
    # One real CVE record lists ~40 Netgear models; only the queried CPE counts.
    item = _nvd_item([
        {"vulnerable": True, "criteria": "cpe:2.3:o:netgear:r6400_firmware:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "9.9.9.9"},
        {"vulnerable": True, "criteria": "cpe:2.3:o:netgear:r7000_firmware:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "1.0.11.128"},
    ])
    assert fvc.extract_nvd_version_range(item, NETGEAR_CPE)["end_excluding"] == "1.0.11.128"


def test_extract_nvd_range_ignores_non_vulnerable_hardware_partners():
    # Axis's real situation: every match for its h: CPE is vulnerable:false,
    # the non-vulnerable partner of an AND-node. Never a "this range is safe"
    # signal, so the honest answer is None - nothing said about this CPE.
    item = _nvd_item([{
        "vulnerable": False,
        "criteria": "cpe:2.3:h:axis:m3216-lve:-:*:*:*:*:*:*:*",
    }])
    assert fvc.extract_nvd_version_range(item, "h:axis:m3216-lve") is None


def test_extract_nvd_range_recurses_into_nested_nodes():
    item = {"cve": {"configurations": [{"nodes": [{"nodes": [{"cpeMatch": [{
        "vulnerable": True,
        "criteria": "cpe:2.3:o:netgear:r7000_firmware:*:*:*:*:*:*:*:*",
        "versionEndIncluding": "1.0.7.2_1.1.93",
    }]}]}]}]}}
    assert fvc.extract_nvd_version_range(item, NETGEAR_CPE)["end_including"] == "1.0.7.2_1.1.93"


def test_extract_nvd_range_reports_disagreeing_ranges_as_ambiguous():
    item = _nvd_item([
        {"vulnerable": True, "criteria": f"cpe:2.3:{NETGEAR_CPE}:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "1.0.11.128"},
        {"vulnerable": True, "criteria": f"cpe:2.3:{NETGEAR_CPE}:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "2.0.0.0"},
    ])
    assert fvc.extract_nvd_version_range(item, NETGEAR_CPE) == {"ambiguous": True}


# -- CSAF extraction --------------------------------------------------------

REAL_CSAF_ADVISORY = {
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


def test_extract_csaf_ranges_reads_the_real_advisory_shape():
    # ICSA-18-240-02, fetched live from CISA's cisagov/CSAF mirror.
    assert fvc.extract_csaf_version_ranges(REAL_CSAF_ADVISORY) == {
        "CVE-2018-7789": {
            "start_including": None, "start_excluding": None,
            "end_including": None, "end_excluding": "1.6.2.0", "unbounded": False,
        },
    }


@pytest.mark.parametrize(
    ("expression", "field", "value"),
    [
        ("<1.6.2.0", "end_excluding", "1.6.2.0"),
        ("<=1.6.2.0", "end_including", "1.6.2.0"),
        (">1.0.0", "start_excluding", "1.0.0"),
        (">=1.0.0", "start_including", "1.0.0"),
    ],
)
def test_parse_csaf_expression_handles_each_operator(expression, field, value):
    assert fvc.parse_csaf_range_expression(expression)[field] == value


def test_parse_csaf_expression_treats_a_bare_version_as_exact():
    parsed = fvc.parse_csaf_range_expression("1.6.2.0")
    assert parsed["start_including"] == "1.6.2.0"
    assert parsed["end_including"] == "1.6.2.0"


def test_parse_csaf_expression_returns_none_rather_than_guessing():
    assert fvc.parse_csaf_range_expression(None) is None
    assert fvc.parse_csaf_range_expression("") is None
    assert fvc.parse_csaf_range_expression("all versions") is None
    assert fvc.parse_csaf_range_expression("<") is None


def test_extract_csaf_ranges_survives_a_malformed_advisory():
    assert fvc.extract_csaf_version_ranges({}) == {}
    assert fvc.extract_csaf_version_ranges({"product_tree": {}, "vulnerabilities": []}) == {}


# -- version_status_for_range ----------------------------------------------


def test_status_affected_uses_the_real_netgear_case():
    # The device really is on 1.0.11.132 and the real fix really is 1.0.11.136.
    status, fixed = fvc.version_status_for_range(
        "V1.0.11.132_10.2.132", {**fvc._empty_range(), "end_excluding": "1.0.11.136"},
    )
    assert status == fvc.STATUS_AFFECTED
    assert fixed == "1.0.11.136"


def test_status_not_affected_uses_the_real_netgear_case():
    # 1.0.11.132 >= 1.0.11.128, hand-verified.
    status, fixed = fvc.version_status_for_range(
        "V1.0.11.132_10.2.132", {**fvc._empty_range(), "end_excluding": "1.0.11.128"},
    )
    assert status == fvc.STATUS_NOT_AFFECTED


def test_status_compares_a_boundary_that_itself_carries_a_suffix():
    # Real NVD value: versionEndIncluding "1.0.7.2_1.1.93". The suffix is
    # discarded on BOTH sides, not just the device's string.
    status, _ = fvc.version_status_for_range(
        "V1.0.11.132_10.2.132", {**fvc._empty_range(), "end_including": "1.0.7.2_1.1.93"},
    )
    assert status == fvc.STATUS_NOT_AFFECTED


def test_status_unbounded_is_affected_no_fix_not_unknown():
    status, fixed = fvc.version_status_for_range(
        "V5.3.0 build 160530", {**fvc._empty_range(), "unbounded": True},
    )
    assert status == fvc.STATUS_AFFECTED_NO_FIX
    assert fixed is None


def test_status_unbounded_resolves_even_when_the_firmware_string_is_unparseable():
    # The assertion "every version is affected" holds regardless of what the
    # device reports, so it must not be downgraded to unknown.
    status, _ = fvc.version_status_for_range("garbage", {**fvc._empty_range(), "unbounded": True})
    assert status == fvc.STATUS_AFFECTED_NO_FIX


def test_status_unknown_for_an_unparseable_firmware_against_a_real_boundary():
    status, _ = fvc.version_status_for_range(
        "210628", {**fvc._empty_range(), "end_excluding": "1.0.11.136"},
    )
    assert status == fvc.STATUS_UNKNOWN


def test_status_unknown_for_a_missing_or_ambiguous_range():
    assert fvc.version_status_for_range("1.0.0", None)[0] == fvc.STATUS_UNKNOWN
    assert fvc.version_status_for_range("1.0.0", {"ambiguous": True})[0] == fvc.STATUS_UNKNOWN


def test_status_not_affected_when_below_a_start_bound():
    status, _ = fvc.version_status_for_range(
        "1.0.0", {**fvc._empty_range(), "start_including": "2.0.0", "end_excluding": "3.0.0"},
    )
    assert status == fvc.STATUS_NOT_AFFECTED


def test_status_pads_unequal_length_versions():
    status, _ = fvc.version_status_for_range(
        "1.4", {**fvc._empty_range(), "end_including": "1.4.0"},
    )
    assert status == fvc.STATUS_AFFECTED


# -- rollup_firmware_currency ----------------------------------------------


def _cve(status, fixed=None):
    return {"id": "CVE-X", "version_status": status, "fixed_version": fixed}


def test_rollup_outdated_takes_precedence_and_names_the_earliest_fix():
    result = fvc.rollup_firmware_currency(
        [
            _cve(fvc.STATUS_AFFECTED, "1.0.11.136"),
            _cve(fvc.STATUS_AFFECTED, "1.0.11.134"),
            _cve(fvc.STATUS_AFFECTED_NO_FIX),
            _cve(fvc.STATUS_NOT_AFFECTED),
        ],
        ["nvd_version_range"],
    )
    assert result["status"] == fvc.CURRENCY_OUTDATED
    assert "1.0.11.134" in result["reason"]
    assert result["affected_count"] == 2


def test_rollup_reports_affected_no_fix_rather_than_hiding_it_as_unknown():
    # The Hikvision/Yale/Sonos case: a real, definite CVE with no fix to
    # point at. Reporting "unknown" here would bury a KEV-listed finding.
    result = fvc.rollup_firmware_currency([_cve(fvc.STATUS_AFFECTED_NO_FIX)], ["nvd_version_range"])
    assert result["status"] == fvc.CURRENCY_AFFECTED_NO_FIX
    assert "no fixed version published" in result["reason"]


def test_rollup_current_requires_something_resolved_and_nothing_unresolved():
    assert fvc.rollup_firmware_currency(
        [_cve(fvc.STATUS_NOT_AFFECTED), _cve(fvc.STATUS_NOT_AFFECTED)], ["nvd_version_range"],
    )["status"] == fvc.CURRENCY_CURRENT


def test_rollup_never_claims_current_when_anything_is_unresolved():
    # A false "you are up to date" is the worst possible output here.
    assert fvc.rollup_firmware_currency(
        [_cve(fvc.STATUS_NOT_AFFECTED), _cve(fvc.STATUS_UNKNOWN)], ["nvd_version_range"],
    )["status"] == fvc.CURRENCY_UNKNOWN


def test_rollup_of_no_cves_at_all_is_unknown_never_current():
    result = fvc.rollup_firmware_currency([], ["nvd_version_range"])
    assert result["status"] == fvc.CURRENCY_UNKNOWN
    assert "not a clean result" in result["reason"]


def test_rollup_records_which_sources_were_consulted():
    result = fvc.rollup_firmware_currency([], ["nvd_version_range", "schneider_csaf"])
    assert result["sources_checked"] == ["nvd_version_range", "schneider_csaf"]
