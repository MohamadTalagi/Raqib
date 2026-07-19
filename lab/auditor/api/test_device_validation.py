import pytest

from device_validation import (
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


def test_localhost_rejected():
    with pytest.raises(ValidationError):
        validate_host("localhost")


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
