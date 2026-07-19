import pytest

from device_validation import (
    INFRASTRUCTURE_HOSTS,
    ValidationError,
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
