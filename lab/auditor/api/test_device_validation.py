import pytest

from device_validation import (
    INFRASTRUCTURE_HOSTS,
    MIN_SCOPE_PREFIX_LENGTH,
    PRIVATE_RANGES,
    PROTECTED_RANGES,
    ValidationError,
    configure_allowed_networks,
    validate_device_id,
    validate_host,
    validate_port,
    validate_service_type,
)


def test_valid_container_name_accepted():
    assert validate_host("device-insecure") == "device-insecure"


def test_valid_in_range_ip_accepted():
    assert validate_host("172.30.0.9") == "172.30.0.9"


def test_argv_injection_rejected():
    # A leading dash makes this an nmap FLAG, not a target.
    with pytest.raises(ValidationError):
        validate_host("--script=http-shellshock")


def test_infrastructure_hostname_rejected():
    for name in ("auditor-api", "auditor-database", "auditor-web", "auditor-worker"):
        with pytest.raises(ValidationError):
            validate_host(name)


def test_out_of_range_private_ips_rejected():
    for ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.169.254", "0.0.0.0"):
        with pytest.raises(ValidationError):
            validate_host(ip)


def test_octal_encoded_in_range_ip_rejected():
    # Same address as 172.30.0.1 to a resolver, different string to a regex.
    with pytest.raises(ValidationError):
        validate_host("0172.030.0.1")


def test_localhost_rejected_as_loopback():
    with pytest.raises(ValidationError) as exc_info:
        validate_host("localhost")
    # localhost must be rejected as a loopback alias, not as infrastructure
    assert "loopback" in exc_info.value.message.lower()
    assert "infrastructure" not in exc_info.value.message.lower()


def test_device_id_rejects_path_traversal_and_spaces_and_uppercase():
    for bad in ("../etc/passwd", "device insecure", "Device-Insecure", "", "-leading"):
        with pytest.raises(ValidationError):
            validate_device_id(bad)


def test_device_id_accepts_normal_name():
    assert validate_device_id("device-insecure") == "device-insecure"


def test_port_bounds():
    assert validate_port(443) == 443
    for bad in (0, -1, 65536, 99999):
        with pytest.raises(ValidationError):
            validate_port(bad)


def test_service_type_enum():
    assert validate_service_type("https") == "https"
    with pytest.raises(ValidationError):
        validate_service_type("gopher")


def test_pure_hex_hostnames_accepted():
    # Valid container names composed entirely of hex letters must be accepted
    for hostname in ("cafe", "beef", "deadbeef", "facade"):
        assert validate_host(hostname) == hostname


def test_octal_encoded_ip_still_rejected():
    # Ensure the fix doesn't over-correct: octal-encoded IPs must still be rejected
    with pytest.raises(ValidationError) as exc_info:
        validate_host("0172.030.0.1")
    assert "looks like an IP but is not a valid address" in exc_info.value.message


def test_infrastructure_hosts_exact_set():
    # INFRASTRUCTURE_HOSTS must contain exactly the four auditor-* names, not localhost
    expected = {"auditor-api", "auditor-database", "auditor-web", "auditor-worker"}
    assert INFRASTRUCTURE_HOSTS == expected


def test_integer_form_of_ip_rejected():
    # glibc's getaddrinfo resolves this bare integer as 8.8.8.8 via inet_aton
    # semantics, even though it has neither "." nor ":" and matches NAME_PATTERN.
    with pytest.raises(ValidationError):
        validate_host("134744072")


def test_hex_form_of_ip_rejected():
    # Hex form of 8.8.8.8 - contains no "." or ":" either, and NAME_PATTERN
    # matches it too, so it must be caught by the integer/hex literal check.
    with pytest.raises(ValidationError):
        validate_host("0x8080808")


def test_integer_form_of_in_range_ip_still_rejected():
    # Integer form of 172.30.0.1 (an in-range address). The point isn't that
    # the resolved address happens to be in range - it's that this notation
    # is never an acceptable host value in the first place.
    with pytest.raises(ValidationError):
        validate_host("2887778305")


def test_bare_number_rejected():
    with pytest.raises(ValidationError):
        validate_host("12345")


def test_legitimate_names_still_accepted():
    for hostname in ("device-insecure", "cam2", "a1"):
        assert validate_host(hostname) == hostname


# -- Network Scope: configurable allowlist -----------------------------------


def test_configure_allowed_networks_accepts_a_host_in_the_new_range():
    configure_allowed_networks(["172.30.0.0/24", "10.5.0.0/24"])
    assert validate_host("10.5.0.9") == "10.5.0.9"
    assert validate_host("172.30.0.5") == "172.30.0.5"


def test_configure_allowed_networks_rejects_a_host_outside_every_configured_range():
    configure_allowed_networks(["10.5.0.0/24"])
    with pytest.raises(ValidationError):
        validate_host("172.30.0.5")


def test_configure_allowed_networks_replaces_wholesale_not_additively():
    configure_allowed_networks(["172.30.0.0/24"])
    configure_allowed_networks(["10.5.0.0/24"])
    with pytest.raises(ValidationError):
        validate_host("172.30.0.5")
    assert validate_host("10.5.0.9") == "10.5.0.9"


def test_private_ranges_cover_all_of_rfc1918_and_link_local():
    import ipaddress

    for candidate in ("10.1.2.3", "172.16.5.5", "172.31.5.5", "192.168.1.1", "169.254.1.1"):
        address = ipaddress.ip_address(candidate)
        assert any(address in net for net in PRIVATE_RANGES)


def test_protected_ranges_include_this_labs_backend_network_and_loopback():
    import ipaddress

    assert ipaddress.ip_network("172.31.0.0/24") in PROTECTED_RANGES
    assert any(ipaddress.ip_address("127.0.0.1") in net for net in PROTECTED_RANGES)


def test_min_scope_prefix_length_is_16_or_narrower_bound():
    assert MIN_SCOPE_PREFIX_LENGTH == 16
