from lab.auditor.worker.scan_scripts.sbom import build_cyclonedx_sbom


def test_build_cyclonedx_sbom_is_a_minimal_valid_document():
    sbom = build_cyclonedx_sbom([("openssl", "1.0.1e")])
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["components"] == [
        {"type": "library", "name": "openssl", "version": "1.0.1e", "purl": "pkg:generic/openssl@1.0.1e"},
    ]


def test_build_cyclonedx_sbom_uses_a_verified_cpe_override_when_known():
    # "mosquitto" is a real Grype/NVD under-match case: the naive generic
    # purl found zero CVEs because the real CPE vendor ("eclipse") isn't the
    # product name - confirmed live during the vulnerability-intelligence
    # spike. An explicit cpe fixes it.
    sbom = build_cyclonedx_sbom([("mosquitto", "1.4.10")])
    [component] = sbom["components"]
    assert component["cpe"] == "cpe:2.3:a:eclipse:mosquitto:1.4.10:*:*:*:*:*:*:*"
    assert "purl" not in component


def test_build_cyclonedx_sbom_is_deterministic_and_handles_multiple_packages():
    packages = [("openssl", "1.0.1e"), ("busybox", "1.19.4")]
    assert build_cyclonedx_sbom(packages) == build_cyclonedx_sbom(packages)
    assert len(build_cyclonedx_sbom(packages)["components"]) == 2


def test_build_cyclonedx_sbom_handles_empty_package_list():
    assert build_cyclonedx_sbom([])["components"] == []
