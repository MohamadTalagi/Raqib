from policies.catalog.scan_tests import SCAN_CATALOG, is_applicable

HTTP_TARGET = {
    "device_id": "device-insecure", "host": "device-insecure",
    "service_type": "http", "port": 80,
}
MQTT_TARGET = {
    "device_id": "mqtt-broker-insecure", "host": "mqtt-broker-insecure",
    "service_type": "mqtt", "port": 1883,
}
HTTPS_TARGET = {
    "device_id": "device-hardened", "host": "device-hardened",
    "service_type": "https", "port": 443,
}
HTTP_NONDEFAULT_PORT_TARGET = {
    "device_id": "device-insecure", "host": "device-insecure",
    "service_type": "http", "port": 8080,
}
HTTPS_NONDEFAULT_PORT_TARGET = {
    "device_id": "device-hardened", "host": "device-hardened",
    "service_type": "https", "port": 8443,
}


def test_portscan_applies_to_any_service_type():
    assert is_applicable(HTTP_TARGET, "TEST-NET-PORTSCAN")
    assert is_applicable(MQTT_TARGET, "TEST-NET-PORTSCAN")


def test_http_tests_do_not_apply_to_mqtt():
    assert not is_applicable(MQTT_TARGET, "TEST-AUTH-DEFAULT-CREDS")
    assert not is_applicable(MQTT_TARGET, "TEST-HTTP-HEADERS")


def test_http_tests_apply_to_http_services():
    assert is_applicable(HTTP_TARGET, "TEST-AUTH-DEFAULT-CREDS")
    assert is_applicable(HTTP_TARGET, "TEST-HTTP-HEADERS")


def test_unknown_test_id_is_never_applicable():
    assert not is_applicable(HTTP_TARGET, "TEST-DOES-NOT-EXIST")


def test_login_command_uses_target_scheme_and_host():
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"](HTTP_TARGET)
    assert command[0] == "curl"
    assert "http://device-insecure/login" in command
    # argv list, never a shell string
    assert all(isinstance(part, str) for part in command)


def test_login_command_omits_insecure_flag_for_http():
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"](HTTP_TARGET)
    assert "-k" not in command


def test_login_command_uses_https_and_insecure_flag_for_hardened():
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"](HTTPS_TARGET)
    assert "https://device-hardened/login" in command
    assert "-k" in command  # self-signed lab certs


def test_https_target_builds_https_url_with_insecure_flag():
    command = SCAN_CATALOG["TEST-HTTP-HEADERS"]["build_command"](HTTPS_TARGET)
    assert "https://device-hardened/" in command
    assert "-k" in command  # self-signed lab certs


def test_headers_command_omits_insecure_flag_for_http():
    command = SCAN_CATALOG["TEST-HTTP-HEADERS"]["build_command"](HTTP_TARGET)
    assert "-k" not in command


def test_login_command_includes_nondefault_http_port():
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"](HTTP_NONDEFAULT_PORT_TARGET)
    assert "http://device-insecure:8080/login" in command


def test_login_command_on_default_http_port_is_byte_identical_to_no_port():
    # Regression: the resolved port must never leak into the URL when it is
    # the scheme default - historical evidence records reference this exact
    # command string.
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"](HTTP_TARGET)
    assert command == [
        "curl", "-s", "-X", "POST", "http://device-insecure/login",
        "-d", "username=admin&password=admin",
    ]


def test_login_command_on_default_https_port_omits_port():
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"](HTTPS_TARGET)
    assert "https://device-hardened/login" in command
    assert "https://device-hardened:443/login" not in command


def test_login_command_includes_nondefault_https_port():
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"](HTTPS_NONDEFAULT_PORT_TARGET)
    assert "https://device-hardened:8443/login" in command


def test_headers_command_includes_nondefault_http_port():
    command = SCAN_CATALOG["TEST-HTTP-HEADERS"]["build_command"](HTTP_NONDEFAULT_PORT_TARGET)
    assert "http://device-insecure:8080/" in command


def test_headers_command_on_default_http_port_is_byte_identical_to_no_port():
    # Regression: byte-identical to the pre-fix command for default-port
    # targets (every seeded lab device uses http:80 or https:443 today).
    command = SCAN_CATALOG["TEST-HTTP-HEADERS"]["build_command"](HTTP_TARGET)
    assert command == ["curl", "-s", "-I", "http://device-insecure/"]


def test_headers_command_on_default_https_port_omits_port():
    command = SCAN_CATALOG["TEST-HTTP-HEADERS"]["build_command"](HTTPS_TARGET)
    assert "https://device-hardened/" in command
    assert "https://device-hardened:443/" not in command


def test_headers_command_includes_nondefault_https_port():
    command = SCAN_CATALOG["TEST-HTTP-HEADERS"]["build_command"](HTTPS_NONDEFAULT_PORT_TARGET)
    assert "https://device-hardened:8443/" in command


def test_portscan_scans_the_full_port_range():
    command = SCAN_CATALOG["TEST-NET-PORTSCAN"]["build_command"](MQTT_TARGET)
    assert command[0] == "nmap"
    assert "-p-" in command
    assert "mqtt-broker-insecure" in command


def test_parse_nmap_observations_detects_telnet_open():
    output = "23/tcp   open  telnet\n80/tcp   open  http\n"
    obs = SCAN_CATALOG["TEST-NET-PORTSCAN"]["parse_observations"](MQTT_TARGET, output)
    assert obs == {"open_ports": [23, 80], "telnet_open": True}


def test_parse_nmap_observations_no_telnet():
    output = "80/tcp   open  http\n"
    obs = SCAN_CATALOG["TEST-NET-PORTSCAN"]["parse_observations"](MQTT_TARGET, output)
    assert obs == {"open_ports": [80], "telnet_open": False}


def test_parse_login_observations_detects_success():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"](
        HTTP_TARGET, '{"status":"ok","message":"Login successful"}'
    )
    assert obs == {"default_creds": True}


def test_parse_login_observations_detects_failure():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"](
        HTTPS_TARGET, '{"detail":"Invalid credentials"}'
    )
    assert obs == {"default_creds": False}


def test_parse_headers_observations_flags_missing_headers():
    obs = SCAN_CATALOG["TEST-HTTP-HEADERS"]["parse_observations"](
        HTTP_TARGET, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
    )
    assert obs == {"missing_security_headers": ["X-Frame-Options", "Content-Security-Policy"]}


def test_parse_headers_observations_empty_when_present():
    output = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'\r\n"
    obs = SCAN_CATALOG["TEST-HTTP-HEADERS"]["parse_observations"](HTTPS_TARGET, output)
    assert obs == {"missing_security_headers": []}
