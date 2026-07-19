from policies.catalog.scan_tests import SCAN_CATALOG, is_applicable

HTTP_TARGET = {
    "device_id": "device-insecure", "host": "device-insecure",
    "service_type": "http", "port": 80,
}
MQTT_TARGET = {
    "device_id": "mqtt-broker-insecure", "host": "mqtt-broker-insecure",
    "service_type": "mqtt", "port": 1883,
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


def test_https_target_builds_https_url_with_insecure_flag():
    target = {
        "device_id": "device-hardened", "host": "device-hardened",
        "service_type": "https", "port": 443,
    }
    command = SCAN_CATALOG["TEST-HTTP-HEADERS"]["build_command"](target)
    assert "https://device-hardened/" in command
    assert "-k" in command  # self-signed lab certs


def test_portscan_targets_the_service_port():
    command = SCAN_CATALOG["TEST-NET-PORTSCAN"]["build_command"](MQTT_TARGET)
    assert command[0] == "nmap"
    assert "mqtt-broker-insecure" in command
