from policies.catalog.scan_tests import SCAN_CATALOG, is_applicable, is_firmware_test

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


# --- categories ---

def test_web_and_auth_tests_are_categorized():
    for test_id in (
        "TEST-AUTH-DEFAULT-CREDS", "TEST-HTTP-HEADERS", "TEST-AUTH-ANON-ACCESS",
        "TEST-AUTH-SESSION", "TEST-ADMIN-UNAUTH",
    ):
        assert SCAN_CATALOG[test_id]["category"] == "web-and-auth"


def test_network_and_protocol_tests_are_categorized():
    for test_id in (
        "TEST-NET-PORTSCAN", "TEST-NET-HTTP-INSPECT", "TEST-MQTT-OPEN",
        "TEST-TLS-CONFIG", "TEST-NET-PKTCAPTURE",
    ):
        assert SCAN_CATALOG[test_id]["category"] == "network-and-protocol"


# --- TEST-AUTH-ANON-ACCESS ---

def test_anon_access_command_hits_config_endpoint_with_no_credentials():
    command = SCAN_CATALOG["TEST-AUTH-ANON-ACCESS"]["build_command"](HTTP_TARGET)
    assert command == ["curl", "-s", "http://device-insecure/api/config"]


def test_parse_anon_access_observations_flags_exposed_api_key():
    output = '{"cred_mode":"default","mqtt_host":"mqtt-broker-insecure","api_key":"abc123"}'
    obs = SCAN_CATALOG["TEST-AUTH-ANON-ACCESS"]["parse_observations"](HTTP_TARGET, output)
    assert obs["anonymous_access_allowed"] is True
    assert obs["api_key_exposed"] is True
    assert len(obs["notes"]) == 2


def test_parse_anon_access_observations_no_api_key():
    output = '{"cred_mode":"changed","mqtt_host":"mqtt-broker-secure"}'
    obs = SCAN_CATALOG["TEST-AUTH-ANON-ACCESS"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["anonymous_access_allowed"] is True
    assert obs["api_key_exposed"] is False
    assert len(obs["notes"]) == 1


# --- TEST-AUTH-SESSION ---

def test_session_command_chains_login_and_dashboard_in_one_curl():
    command = SCAN_CATALOG["TEST-AUTH-SESSION"]["build_command"](HTTP_TARGET)
    assert command[0] == "curl"
    assert "http://device-insecure/login" in command
    assert "http://device-insecure/dashboard" in command
    assert "--next" in command


def test_parse_session_observations_detects_no_cookie_and_open_dashboard():
    output = (
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        '{"status":"ok","message":"Login successful"}'
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>dashboard</html>"
    )
    obs = SCAN_CATALOG["TEST-AUTH-SESSION"]["parse_observations"](HTTP_TARGET, output)
    assert obs["session_cookie_issued"] is False
    assert obs["dashboard_accessible_without_session"] is True
    assert len(obs["notes"]) == 2


def test_parse_session_observations_detects_cookie_issued():
    output = (
        "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\n\r\n{}"
        "HTTP/1.1 401 Unauthorized\r\n\r\n"
    )
    obs = SCAN_CATALOG["TEST-AUTH-SESSION"]["parse_observations"](HTTP_TARGET, output)
    assert obs["session_cookie_issued"] is True
    assert obs["dashboard_accessible_without_session"] is False
    assert len(obs["notes"]) == 1


# --- TEST-ADMIN-UNAUTH ---

def test_admin_unauth_command_hits_reset_endpoint():
    command = SCAN_CATALOG["TEST-ADMIN-UNAUTH"]["build_command"](HTTP_TARGET)
    assert command == ["curl", "-s", "-i", "http://device-insecure/api/admin/reset"]


def test_parse_admin_unauth_observations_detects_unauthenticated_success():
    obs = SCAN_CATALOG["TEST-ADMIN-UNAUTH"]["parse_observations"](
        HTTP_TARGET, 'HTTP/1.1 200 OK\r\n\r\n{"status":"reset-triggered"}'
    )
    assert obs["admin_unauthenticated"] is True
    assert obs["notes"]


def test_parse_admin_unauth_observations_detects_protected_endpoint():
    obs = SCAN_CATALOG["TEST-ADMIN-UNAUTH"]["parse_observations"](
        HTTPS_TARGET, 'HTTP/1.1 401 Unauthorized\r\n\r\n{"detail":"Unauthorized"}'
    )
    assert obs["admin_unauthenticated"] is False
    assert obs["notes"]


# --- TEST-NET-HTTP-INSPECT ---

def test_http_inspect_command_requests_root_with_version_writeout():
    command = SCAN_CATALOG["TEST-NET-HTTP-INSPECT"]["build_command"](HTTP_TARGET)
    assert command[0] == "curl"
    assert "http://device-insecure/" in command
    assert "-w" in command


def test_parse_http_inspect_observations_extracts_banner_and_version():
    output = "HTTP/1.1 200 OK\r\nServer: uvicorn\r\n\r\n<html></html>\nHTTP_VERSION:1.1\n"
    obs = SCAN_CATALOG["TEST-NET-HTTP-INSPECT"]["parse_observations"](HTTP_TARGET, output)
    assert obs["server_banner"] == "uvicorn"
    assert obs["http_version"] == "1.1"
    assert obs["banner_discloses_framework"] is True
    # "uvicorn" alone has no version component to look up
    assert obs["component_advisory"] is None
    assert obs["notes"]


def test_parse_http_inspect_observations_handles_missing_server_header():
    output = "HTTP/1.1 200 OK\r\n\r\n<html></html>\nHTTP_VERSION:1.1\n"
    obs = SCAN_CATALOG["TEST-NET-HTTP-INSPECT"]["parse_observations"](HTTP_TARGET, output)
    assert obs["server_banner"] is None
    assert obs["http_version"] == "1.1"
    assert obs["banner_discloses_framework"] is False
    assert obs["component_advisory"] is None


def test_parse_http_inspect_observations_looks_up_a_versioned_banner():
    output = "HTTP/1.1 200 OK\r\nServer: openssl/1.0.1e\r\n\r\n<html></html>\nHTTP_VERSION:1.1\n"
    obs = SCAN_CATALOG["TEST-NET-HTTP-INSPECT"]["parse_observations"](HTTP_TARGET, output)
    assert obs["component_advisory"]["outdated"] is True
    assert {c["id"] for c in obs["component_advisory"]["cves"]} == {"CVE-2014-0160", "CVE-2014-0224"}


# --- TEST-MQTT-OPEN ---

def test_mqtt_command_subscribes_with_a_bounded_wait():
    command = SCAN_CATALOG["TEST-MQTT-OPEN"]["build_command"](MQTT_TARGET)
    assert command[0] == "mosquitto_sub"
    assert "mqtt-broker-insecure" in command
    assert "-W" in command


def test_parse_mqtt_observations_detects_anonymous_connection():
    output = "devices/device-insecure/telemetry {\"device_id\": \"device-insecure\"}\n"
    obs = SCAN_CATALOG["TEST-MQTT-OPEN"]["parse_observations"](MQTT_TARGET, output)
    assert obs["mqtt_tls"] is False
    assert obs["mqtt_anonymous"] is True
    assert len(obs["notes"]) == 2


def test_parse_mqtt_observations_detects_rejected_connection():
    secure_target = {
        "device_id": "mqtt-broker-secure", "host": "mqtt-broker-secure",
        "service_type": "mqtts", "port": 8883,
    }
    output = "Connection error: Connection Refused: not authorised.\n"
    obs = SCAN_CATALOG["TEST-MQTT-OPEN"]["parse_observations"](secure_target, output)
    assert obs["mqtt_tls"] is True
    assert obs["mqtt_anonymous"] is False
    assert obs["notes"] == ["Anonymous access was rejected and the connection is TLS-protected."]


# --- TEST-TLS-CONFIG ---

def test_tls_command_connects_with_brief_output():
    command = SCAN_CATALOG["TEST-TLS-CONFIG"]["build_command"](HTTPS_TARGET)
    assert command == ["openssl", "s_client", "-connect", "device-hardened:443", "-brief"]


def test_parse_tls_observations_detects_weak_cert():
    # Real committed raw output for the weak 1024-bit cert (document-store/raw/EV-2026-07-08-0019.txt)
    output = (
        "Connecting to 172.30.0.2\n"
        "depth=0 CN=device-partial\n"
        "verify error:num=66:EE certificate key too weak\n"
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.3\n"
        "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
        "DONE\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["tls_version"] == "TLSv1.3"
    assert obs["weak_cipher"] is True
    assert obs["notes"]


def test_parse_tls_observations_detects_strong_cert():
    # Real committed raw output for the strong 2048-bit cert (document-store/raw/EV-2026-07-08-0020.txt)
    output = (
        "Connecting to 172.30.0.6\n"
        "depth=0 CN=device-hardened\n"
        "verify error:num=20:unable to get local issuer certificate\n"
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.3\n"
        "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
        "DONE\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["tls_version"] == "TLSv1.3"
    assert obs["weak_cipher"] is False
    assert obs["notes"] == ["No weak key or deprecated protocol version detected."]


def test_parse_tls_observations_flags_deprecated_protocol_version():
    output = (
        "Connecting to 172.30.0.2\n"
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.1\n"
        "DONE\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["tls_version"] == "TLSv1.1"
    assert any("deprecated" in n for n in obs["notes"])


# --- TEST-NET-PKTCAPTURE ---

def test_pktcapture_command_invokes_helper_script():
    command = SCAN_CATALOG["TEST-NET-PKTCAPTURE"]["build_command"](HTTP_TARGET)
    assert command == [
        "python3", "/work/lab/auditor/worker/scan_scripts/packet_capture.py",
        "device-insecure", "80", "http",
    ]


def test_parse_pktcapture_observations_detects_plaintext_request():
    output = "packets_captured=6\nplaintext_get_visible=True\n--- packet summary ---\n...\n"
    obs = SCAN_CATALOG["TEST-NET-PKTCAPTURE"]["parse_observations"](HTTP_TARGET, output)
    assert obs["packets_captured"] == 6
    assert obs["plaintext_get_visible"] is True
    assert obs["notes"]


def test_parse_pktcapture_observations_detects_no_plaintext_on_https():
    output = "packets_captured=10\nplaintext_get_visible=False\n--- packet summary ---\n...\n"
    obs = SCAN_CATALOG["TEST-NET-PKTCAPTURE"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["packets_captured"] == 10
    assert obs["plaintext_get_visible"] is False
    assert obs["notes"] == ["No plaintext application data was visible in the capture."]


def test_portscan_scans_the_full_port_range():
    command = SCAN_CATALOG["TEST-NET-PORTSCAN"]["build_command"](MQTT_TARGET)
    assert command[0] == "nmap"
    assert "-p-" in command
    assert "mqtt-broker-insecure" in command


def test_parse_nmap_observations_detects_telnet_open():
    output = "23/tcp   open  telnet\n80/tcp   open  http\n"
    obs = SCAN_CATALOG["TEST-NET-PORTSCAN"]["parse_observations"](MQTT_TARGET, output)
    assert obs["open_ports"] == [23, 80]
    assert obs["telnet_open"] is True
    assert obs["services"] == [
        {"port": 23, "service": "telnet", "version": None},
        {"port": 80, "service": "http", "version": None},
    ]
    assert any("Telnet" in n for n in obs["notes"])


def test_parse_nmap_observations_no_telnet():
    output = "80/tcp   open  http\n"
    obs = SCAN_CATALOG["TEST-NET-PORTSCAN"]["parse_observations"](MQTT_TARGET, output)
    assert obs["open_ports"] == [80]
    assert obs["telnet_open"] is False
    assert obs["notes"] == []


def test_parse_nmap_observations_captures_version_when_disclosed():
    output = "80/tcp   open  http    Werkzeug httpd 2.0.1 (Python 3.9.1)\n"
    obs = SCAN_CATALOG["TEST-NET-PORTSCAN"]["parse_observations"](MQTT_TARGET, output)
    assert obs["services"] == [
        {"port": 80, "service": "http", "version": "Werkzeug httpd 2.0.1 (Python 3.9.1)"},
    ]
    assert any("disclosed version information" in n for n in obs["notes"])


def test_parse_login_observations_detects_success():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"](
        HTTP_TARGET, '{"status":"ok","message":"Login successful"}'
    )
    assert obs["default_creds"] is True
    assert obs["notes"]


def test_parse_login_observations_detects_failure():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"](
        HTTPS_TARGET, '{"detail":"Invalid credentials"}'
    )
    assert obs["default_creds"] is False
    assert obs["notes"] == ["Default admin/admin credentials were rejected."]


def test_parse_headers_observations_flags_missing_headers():
    obs = SCAN_CATALOG["TEST-HTTP-HEADERS"]["parse_observations"](
        HTTP_TARGET, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
    )
    assert obs["missing_security_headers"] == ["X-Frame-Options", "Content-Security-Policy"]
    assert len(obs["notes"]) == 2


def test_parse_headers_observations_empty_when_present():
    output = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'\r\n"
    obs = SCAN_CATALOG["TEST-HTTP-HEADERS"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["missing_security_headers"] == []
    assert obs["notes"] == ["Both checked security headers are present."]


# --- firmware tests: category, is_firmware_test, and command/parse shapes ---

FIRMWARE_TEST_IDS = (
    "TEST-FW-VERSION", "TEST-FW-CONFIG", "TEST-FW-SECRETS", "TEST-FW-APIKEY",
    "TEST-FW-CERTKEY", "TEST-FW-MANIFEST", "TEST-FW-UPDATESCRIPT",
)

FIRMWARE_TARGET = {"device_id": "device-insecure", "host": None, "service_type": None, "port": None}


def test_firmware_tests_are_categorized_and_flagged():
    for test_id in FIRMWARE_TEST_IDS:
        assert SCAN_CATALOG[test_id]["category"] == "firmware"
        assert is_firmware_test(test_id)


def test_non_firmware_tests_are_not_flagged():
    assert not is_firmware_test("TEST-NET-PORTSCAN")
    assert not is_firmware_test("TEST-DOES-NOT-EXIST")


def test_firmware_tests_never_match_a_real_service_type():
    # applicable_service_types=() means is_applicable() must return False no
    # matter what service_type a candidate target carries - firmware tests
    # are gated entirely through is_firmware_test(), never is_applicable().
    for test_id in FIRMWARE_TEST_IDS:
        assert not is_applicable(HTTP_TARGET, test_id)
        assert not is_applicable(HTTPS_TARGET, test_id)
        assert not is_applicable(MQTT_TARGET, test_id)


def test_firmware_commands_invoke_the_check_script_with_device_id_and_check_name():
    expected_check_names = {
        "TEST-FW-VERSION": "version",
        "TEST-FW-CONFIG": "config",
        "TEST-FW-SECRETS": "secrets",
        "TEST-FW-APIKEY": "apikey",
        "TEST-FW-CERTKEY": "certkey",
        "TEST-FW-MANIFEST": "manifest",
        "TEST-FW-UPDATESCRIPT": "updatescript",
    }
    for test_id, check_name in expected_check_names.items():
        command = SCAN_CATALOG[test_id]["build_command"](FIRMWARE_TARGET)
        assert command == [
            "python3", "/work/lab/auditor/worker/scan_scripts/firmware_check.py",
            "device-insecure", check_name,
        ]


def test_parse_fw_version_observations():
    obs = SCAN_CATALOG["TEST-FW-VERSION"]["parse_observations"](
        FIRMWARE_TARGET, "version_file_present=True\nfirmware_version=1.0.0-old\n"
    )
    assert obs["version_file_present"] is True
    assert obs["firmware_version"] == "1.0.0-old"
    assert obs["notes"]


def test_parse_fw_version_observations_when_absent():
    obs = SCAN_CATALOG["TEST-FW-VERSION"]["parse_observations"](FIRMWARE_TARGET, "version_file_present=False\n")
    assert obs["version_file_present"] is False
    assert obs["firmware_version"] is None
    assert obs["notes"]


def test_parse_fw_config_observations():
    obs = SCAN_CATALOG["TEST-FW-CONFIG"]["parse_observations"](
        FIRMWARE_TARGET, "config_files_present=True\nconfig_files=etc/config.ini\n"
    )
    assert obs["config_files_present"] is True
    assert obs["config_files"] == ["etc/config.ini"]
    assert obs["notes"]


def test_parse_fw_secrets_observations():
    obs = SCAN_CATALOG["TEST-FW-SECRETS"]["parse_observations"](FIRMWARE_TARGET, "hardcoded_secret_found=True\n")
    assert obs["hardcoded_secret_found"] is True
    assert obs["notes"]


def test_parse_fw_apikey_observations():
    obs = SCAN_CATALOG["TEST-FW-APIKEY"]["parse_observations"](FIRMWARE_TARGET, "api_key_found=False\n")
    assert obs["api_key_found"] is False
    assert obs["notes"] == ["No embedded API key pattern matched in the archive."]


def test_parse_fw_certkey_observations():
    obs = SCAN_CATALOG["TEST-FW-CERTKEY"]["parse_observations"](FIRMWARE_TARGET, "cert_or_key_present=True\n")
    assert obs["cert_or_key_present"] is True
    assert obs["notes"]


def test_parse_fw_manifest_observations():
    output = "manifest_present=True\npackages=openssl:1.0.1e,busybox:1.19.4\n"
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, output)
    assert obs["manifest_present"] is True
    assert [p["name"] for p in obs["packages"]] == ["openssl", "busybox"]
    assert [p["version"] for p in obs["packages"]] == ["1.0.1e", "1.19.4"]
    openssl_pkg = obs["packages"][0]
    assert openssl_pkg["outdated"] is True
    assert {c["id"] for c in openssl_pkg["cves"]} == {"CVE-2014-0160", "CVE-2014-0224"}
    assert "2 of 2" in obs["notes"][0]


def test_parse_fw_manifest_observations_when_absent():
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, "manifest_present=False\npackages=\n")
    assert obs["manifest_present"] is False
    assert obs["packages"] == []
    assert obs["notes"]


def test_parse_fw_updatescript_observations():
    output = "update_script_present=True\nfirst_line=#!/bin/sh\n"
    obs = SCAN_CATALOG["TEST-FW-UPDATESCRIPT"]["parse_observations"](FIRMWARE_TARGET, output)
    assert obs["update_script_present"] is True
    assert obs["update_script_first_line"] == "#!/bin/sh"
    assert obs["notes"]
