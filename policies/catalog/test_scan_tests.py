import pytest

from policies.catalog.scan_tests import SCAN_CATALOG, is_allowed


def test_is_allowed_true_for_known_combo():
    assert is_allowed("device-insecure", "TEST-NET-PORTSCAN") is True


def test_is_allowed_false_for_unknown_test_id():
    assert is_allowed("device-insecure", "TEST-DOES-NOT-EXIST") is False


def test_is_allowed_false_for_device_not_in_allowlist():
    assert is_allowed("telnet-sim", "TEST-AUTH-DEFAULT-CREDS") is False


@pytest.mark.parametrize("test_id", list(SCAN_CATALOG.keys()))
def test_build_command_returns_argv_list_not_shell_string(test_id):
    spec = SCAN_CATALOG[test_id]
    device = spec["allowed_devices"][0]
    command = spec["build_command"](device)
    assert isinstance(command, list)
    assert all(isinstance(part, str) for part in command)
    assert device in command or any(device in part for part in command)


def test_nmap_command_uses_narrow_port_for_telnet_sim():
    command = SCAN_CATALOG["TEST-NET-PORTSCAN"]["build_command"]("telnet-sim")
    assert command == ["nmap", "-sV", "-p", "23", "telnet-sim"]


def test_login_command_uses_https_and_insecure_flag_for_hardened():
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"]("device-hardened")
    assert "https://device-hardened/login" in command
    assert "-sk" in command


def test_login_command_uses_plain_http_for_insecure_device():
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"]("device-insecure")
    assert "http://device-insecure/login" in command
    assert "-sk" not in command


def test_parse_nmap_observations_detects_telnet_open():
    output = "23/tcp   open  telnet\n80/tcp   open  http\n"
    obs = SCAN_CATALOG["TEST-NET-PORTSCAN"]["parse_observations"]("device-insecure", output)
    assert obs == {"open_ports": [23, 80], "telnet_open": True}


def test_parse_nmap_observations_no_telnet():
    output = "80/tcp   open  http\n"
    obs = SCAN_CATALOG["TEST-NET-PORTSCAN"]["parse_observations"]("device-insecure", output)
    assert obs == {"open_ports": [80], "telnet_open": False}


def test_parse_login_observations_detects_success():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"]("device-insecure", '{"status":"ok","message":"Login successful"}')
    assert obs == {"default_creds": True}


def test_parse_login_observations_detects_failure():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"]("device-hardened", '{"detail":"Invalid credentials"}')
    assert obs == {"default_creds": False}


def test_parse_headers_observations_flags_missing_headers():
    obs = SCAN_CATALOG["TEST-HTTP-HEADERS"]["parse_observations"]("device-insecure", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
    assert obs == {"missing_security_headers": ["X-Frame-Options", "Content-Security-Policy"]}


def test_parse_headers_observations_empty_when_present():
    output = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'\r\n"
    obs = SCAN_CATALOG["TEST-HTTP-HEADERS"]["parse_observations"]("device-hardened", output)
    assert obs == {"missing_security_headers": []}
