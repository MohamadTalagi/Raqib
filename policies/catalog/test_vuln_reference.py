from policies.catalog.vuln_reference import lookup_component


def test_known_component_with_real_cves():
    result = lookup_component("openssl", "1.0.1e")
    assert result["outdated"] is True
    assert result["eol"] is True
    assert result["official_patch_available"] is True
    cve_ids = {cve["id"] for cve in result["cves"]}
    assert cve_ids == {"CVE-2014-0160", "CVE-2014-0224"}
    assert all(cve["cvss"] is not None and cve["summary"] for cve in result["cves"])


def test_known_component_without_confident_cves_gets_notes_not_fabrication():
    result = lookup_component("openssl", "1.1.1k")
    assert result["outdated"] is True
    assert result["cves"] == []
    assert result["notes"]


def test_current_component_is_not_outdated():
    result = lookup_component("openssl", "3.0.11")
    assert result["outdated"] is False


def test_lookup_is_case_and_whitespace_insensitive_on_name():
    result = lookup_component("OpenSSL", "1.0.1e")
    assert result["outdated"] is True


def test_unknown_component_returns_honest_unknown_result():
    result = lookup_component("mystery-lib", "9.9.9")
    assert result["outdated"] is None
    assert result["eol"] is None
    assert result["official_patch_available"] is None
    assert result["cves"] == []
    assert "mystery-lib 9.9.9" in result["notes"][0]


def test_unknown_version_of_a_known_component_is_still_unknown():
    result = lookup_component("openssl", "999.0.0")
    assert result["outdated"] is None
    assert result["cves"] == []


def test_result_always_carries_name_and_version():
    for name, version in (("openssl", "1.0.1e"), ("nginx", "1.18.0")):
        result = lookup_component(name, version)
        assert result["name"] == name
        assert result["version"] == version
