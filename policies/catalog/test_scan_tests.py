from policies.catalog.scan_tests import (
    ALL_SERVICE_TYPES,
    SCAN_CATALOG,
    is_applicable,
    is_firmware_test,
    is_network_discovery_test,
)

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


def test_login_command_tries_all_ten_default_credential_pairs_chained():
    from policies.catalog.scan_tests import DEFAULT_CREDENTIAL_PAIRS

    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"](HTTP_TARGET)
    assert len(DEFAULT_CREDENTIAL_PAIRS) == 10
    assert command.count("--next") == 9
    for username, password in DEFAULT_CREDENTIAL_PAIRS:
        assert f"username={username}&password={password}" in command
    # The resolved port must never leak into the URL when it is the scheme
    # default - historical evidence records reference exact command strings.
    assert "http://device-insecure/login" in command
    assert "http://device-insecure:80/login" not in command


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
        "TEST-NET-REACHABILITY", "TEST-NET-PORTSCAN", "TEST-NET-HTTP-INSPECT", "TEST-MQTT-OPEN",
        "TEST-TLS-CONFIG", "TEST-NET-PKTCAPTURE",
    ):
        assert SCAN_CATALOG[test_id]["category"] == "network-and-protocol"


# --- TEST-NET-REACHABILITY ---

def test_reachability_command_invokes_the_check_script():
    command = SCAN_CATALOG["TEST-NET-REACHABILITY"]["build_command"](HTTP_TARGET)
    assert command == [
        "python3", "/work/lab/auditor/worker/scan_scripts/reachability_check.py",
        "device-insecure", "80",
    ]


def test_reachability_is_applicable_to_every_service_type():
    assert SCAN_CATALOG["TEST-NET-REACHABILITY"]["applicable_service_types"] == ALL_SERVICE_TYPES


def test_parse_reachability_observations_true_when_reachable():
    obs = SCAN_CATALOG["TEST-NET-REACHABILITY"]["parse_observations"](HTTP_TARGET, "reachable=True\n")
    assert obs["reachable"] is True
    assert obs["error"] is None


def test_parse_reachability_observations_false_with_error_detail():
    output = "reachable=False\nerror=[Errno 111] Connection refused\n"
    obs = SCAN_CATALOG["TEST-NET-REACHABILITY"]["parse_observations"](HTTP_TARGET, output)
    assert obs["reachable"] is False
    assert "Connection refused" in obs["error"]


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


def test_parse_http_inspect_observations_disclosure_is_not_tied_to_one_named_product():
    # Any registered product's Server header counts as disclosure, not just
    # this lab's own smart-camera app's uvicorn banner.
    output = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html></html>\nHTTP_VERSION:1.1\n"
    obs = SCAN_CATALOG["TEST-NET-HTTP-INSPECT"]["parse_observations"](HTTP_TARGET, output)
    assert obs["server_banner"] == "nginx"
    assert obs["banner_discloses_framework"] is True


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

def test_tls_command_delegates_to_the_cert_check_script():
    command = SCAN_CATALOG["TEST-TLS-CONFIG"]["build_command"](HTTPS_TARGET)
    assert command == [
        "python3", "/work/lab/auditor/worker/scan_scripts/tls_cert_check.py",
        "device-hardened", "443",
    ]


def test_parse_tls_observations_detects_weak_cert():
    # Real committed raw output for the weak 1024-bit cert (document-store/raw/EV-2026-07-08-0019.txt),
    # with tls_cert_check.py's appended notAfter= line for a cert far in the future.
    output = (
        "Connecting to 172.30.0.2\n"
        "depth=0 CN=device-partial\n"
        "verify error:num=66:EE certificate key too weak\n"
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.3\n"
        "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
        "DONE\n"
        "notBefore=Jul  8 00:00:00 2026 GMT\n"
        "notAfter=Jul  8 00:00:00 2036 GMT\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["tls_version"] == "TLSv1.3"
    assert obs["weak_cipher"] is True
    assert obs["cert_expired"] is False
    assert obs["notes"]


def test_parse_tls_observations_detects_strong_cert():
    # Real committed raw output for the strong 2048-bit cert (document-store/raw/EV-2026-07-08-0020.txt).
    output = (
        "Connecting to 172.30.0.6\n"
        "depth=0 CN=device-hardened\n"
        "verify error:num=20:unable to get local issuer certificate\n"
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.3\n"
        "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
        "DONE\n"
        "notBefore=Jul  8 00:00:00 2026 GMT\n"
        "notAfter=Jul  8 00:00:00 2036 GMT\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["tls_version"] == "TLSv1.3"
    assert obs["weak_cipher"] is False
    assert obs["cert_expired"] is False
    assert obs["notes"] == ["No weak key or deprecated protocol version detected."]


def test_parse_tls_observations_flags_deprecated_protocol_version():
    output = (
        "Connecting to 172.30.0.2\n"
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.1\n"
        "DONE\n"
        "notAfter=Jul  8 00:00:00 2036 GMT\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["tls_version"] == "TLSv1.1"
    assert any("deprecated" in n for n in obs["notes"])


def test_parse_tls_observations_flags_an_expired_certificate():
    output = (
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.3\n"
        "DONE\n"
        "notAfter=Jul  8 00:00:00 2020 GMT\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["cert_expired"] is True
    assert any("expired" in n for n in obs["notes"])


def test_parse_tls_observations_reports_unknown_expiry_when_no_dates_present():
    output = "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nDONE\n"
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["cert_expired"] is None
    assert any("Could not determine" in n for n in obs["notes"])


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
    assert "telnet_open" not in obs
    assert obs["services"] == [
        {"port": 23, "service": "telnet", "version": None},
        {"port": 80, "service": "http", "version": None},
    ]
    assert any("Telnet" in n for n in obs["notes"])


def test_parse_nmap_observations_no_telnet():
    output = "80/tcp   open  http\n"
    obs = SCAN_CATALOG["TEST-NET-PORTSCAN"]["parse_observations"](MQTT_TARGET, output)
    assert obs["open_ports"] == [80]
    assert "telnet_open" not in obs
    assert obs["notes"] == []


def test_parse_nmap_observations_captures_version_when_disclosed():
    output = "80/tcp   open  http    Werkzeug httpd 2.0.1 (Python 3.9.1)\n"
    obs = SCAN_CATALOG["TEST-NET-PORTSCAN"]["parse_observations"](MQTT_TARGET, output)
    assert obs["services"] == [
        {"port": 80, "service": "http", "version": "Werkzeug httpd 2.0.1 (Python 3.9.1)"},
    ]
    assert any("disclosed version information" in n for n in obs["notes"])


def _chained_login_output(success_indices: set[int], total: int = 10) -> str:
    chunks = []
    for i in range(total):
        body = '{"status":"ok","message":"Login successful"}' if i in success_indices else '{"detail":"Invalid credentials"}'
        chunks.append(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}")
    return "".join(chunks)


def test_parse_login_observations_detects_success():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"](
        HTTP_TARGET, _chained_login_output({0}),  # index 0 = admin:admin
    )
    assert obs["default_creds"] is True
    assert obs["working_credentials"] == [{"username": "admin", "password": "admin"}]
    assert len(obs["credentials_tried"]) == 10
    assert obs["notes"]


def test_parse_login_observations_detects_failure():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"](
        HTTPS_TARGET, _chained_login_output(set()),
    )
    assert obs["default_creds"] is False
    assert obs["working_credentials"] == []
    assert obs["notes"] == ["None of the 10 tried default credential pairs were accepted."]


def test_parse_login_observations_detects_a_non_admin_pair_working():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"](
        HTTP_TARGET, _chained_login_output({3}),  # index 3 = root:root
    )
    assert obs["default_creds"] is True
    assert obs["working_credentials"] == [{"username": "root", "password": "root"}]
    assert "root:root" in obs["notes"][0]


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


# -- TEST-NET-DISCOVERY (VLAN sweep) ----------------------------------------

DISCOVERY_TARGET = {"device_id": "device-insecure", "host": None, "service_type": None, "port": None}


def test_network_discovery_test_is_categorized_and_flagged():
    assert SCAN_CATALOG["TEST-NET-DISCOVERY"]["category"] == "network-discovery"
    assert is_network_discovery_test("TEST-NET-DISCOVERY")


def test_non_network_discovery_tests_are_not_flagged():
    assert not is_network_discovery_test("TEST-NET-PORTSCAN")
    assert not is_network_discovery_test("TEST-DOES-NOT-EXIST")


def test_network_discovery_test_never_matches_a_real_service_type():
    # applicable_service_types=() - same shape as firmware tests - so
    # is_applicable() must always return False regardless of service_type.
    assert not is_applicable(HTTP_TARGET, "TEST-NET-DISCOVERY")
    assert not is_applicable(HTTPS_TARGET, "TEST-NET-DISCOVERY")
    assert not is_applicable(MQTT_TARGET, "TEST-NET-DISCOVERY")


def test_network_discovery_command_sweeps_the_audit_network_subnet():
    command = SCAN_CATALOG["TEST-NET-DISCOVERY"]["build_command"](DISCOVERY_TARGET)
    assert command[0] == "nmap"
    assert command[-1] == "172.30.0.0/24"
    # Restricted to the small, known signature-port set - not -p- across a
    # /24, so the scan reliably finishes inside job_runner's 30s timeout.
    assert "-p" in command
    ports_arg = command[command.index("-p") + 1]
    assert set(ports_arg.split(",")) == {"22", "23", "80", "443", "1883", "8883"}


def _discovery_output(*blocks: str) -> str:
    preamble = "Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-23 00:00 UTC\n"
    return preamble + "".join(blocks)


def test_parse_network_discovery_classifies_an_iot_signature_host_as_iot():
    output = _discovery_output(
        "Nmap scan report for device-insecure (172.30.0.5)\n"
        "Host is up (0.00012s latency).\n\n"
        "PORT     STATE SERVICE VERSION\n"
        "80/tcp   open  http    Werkzeug httpd 2.0.1 (Python 3.9.7)\n"
        "23/tcp   open  telnet?\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert obs["subnet"] == "172.30.0.0/24"
    assert len(obs["hosts"]) == 1
    host = obs["hosts"][0]
    assert host["ip"] == "172.30.0.5"
    assert host["hostname"] == "device-insecure"
    assert host["open_ports"] == [23, 80]
    assert host["classification"] == "iot_device"
    assert host["confidence"] == "high"
    assert obs["iot_device_count"] == 1


def test_parse_network_discovery_classifies_mqtt_only_host_as_iot():
    output = _discovery_output(
        "Nmap scan report for mqtt-broker-insecure (172.30.0.6)\n"
        "Host is up (0.00010s latency).\n\n"
        "PORT     STATE SERVICE VERSION\n"
        "1883/tcp open  mqtt\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert obs["hosts"][0]["classification"] == "iot_device"


def test_parse_network_discovery_classifies_telnet_only_host_as_uncertain_not_iot():
    # Telnet alone is a generic remote-administration signature shared by
    # plenty of non-IoT network appliances - this must not be asserted as a
    # confident IoT classification.
    output = _discovery_output(
        "Nmap scan report for telnet-sim (172.30.0.9)\n"
        "Host is up (0.00010s latency).\n\n"
        "PORT     STATE SERVICE VERSION\n"
        "23/tcp   open  telnet\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    host = obs["hosts"][0]
    assert host["classification"] == "uncertain"
    assert host["confidence"] == "low"
    assert obs["uncertain_count"] == 1
    assert obs["iot_device_count"] == 0
    assert any("uncertain" in note.lower() for note in obs["notes"])


def test_parse_network_discovery_classifies_host_with_no_signature_ports_as_unknown():
    output = _discovery_output(
        "Nmap scan report for 172.30.0.42\nHost is up (0.00010s latency).\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    host = obs["hosts"][0]
    assert host["ip"] == "172.30.0.42"
    assert host["hostname"] is None
    assert host["open_ports"] == []
    assert host["classification"] == "unknown"
    assert obs["unknown_count"] == 1


def test_parse_network_discovery_does_not_swallow_the_next_port_when_one_has_no_version():
    # Regression (docs/errors/026): a port line with no version text (nmap
    # prints just "23/tcp open  telnet?" with nothing after it) must not let
    # the next port's whole line get absorbed as this port's "version" -
    # caught live against the real device-insecure container, which exposes
    # exactly this shape (telnet with no version immediately followed by an
    # HTTP service that does have one).
    output = _discovery_output(
        "Nmap scan report for device-insecure (172.30.0.6)\n"
        "Host is up (0.000034s latency).\n\n"
        "PORT   STATE SERVICE VERSION\n"
        "23/tcp open  telnet?\n"
        "80/tcp open  http    Uvicorn\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    host = obs["hosts"][0]
    assert host["open_ports"] == [23, 80]
    assert len(host["services"]) == 2
    telnet_entry = next(s for s in host["services"] if s["port"] == 23)
    http_entry = next(s for s in host["services"] if s["port"] == 80)
    assert telnet_entry["version"] is None
    assert http_entry["service"] == "http"
    assert http_entry["version"] == "Uvicorn"
    # 80 is an IoT signature port, so this host must still classify as IoT
    # even though its FIRST port line carried no version text.
    assert host["classification"] == "iot_device"


def test_parse_network_discovery_handles_multiple_hosts_in_one_run():
    output = _discovery_output(
        "Nmap scan report for device-insecure (172.30.0.5)\n"
        "Host is up.\n\nPORT     STATE SERVICE VERSION\n80/tcp   open  http\n\n",
        "Nmap scan report for mqtt-broker-insecure (172.30.0.6)\n"
        "Host is up.\n\nPORT     STATE SERVICE VERSION\n1883/tcp open  mqtt\n\n",
        "Nmap scan report for telnet-sim (172.30.0.9)\n"
        "Host is up.\n\nPORT     STATE SERVICE VERSION\n23/tcp   open  telnet\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert len(obs["hosts"]) == 3
    assert obs["iot_device_count"] == 2
    assert obs["uncertain_count"] == 1
    classifications = {h["ip"]: h["classification"] for h in obs["hosts"]}
    assert classifications["172.30.0.5"] == "iot_device"
    assert classifications["172.30.0.6"] == "iot_device"
    assert classifications["172.30.0.9"] == "uncertain"


def test_parse_network_discovery_notes_explain_docker_environment_limitation():
    # The "keep the classification honest" requirement: MAC-vendor/OS
    # fingerprinting aren't used, and the notes must say why, not just omit
    # them silently.
    output = _discovery_output(
        "Nmap scan report for device-insecure (172.30.0.5)\n"
        "Host is up.\n\nPORT     STATE SERVICE VERSION\n80/tcp   open  http\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert any("mac" in note.lower() or "docker" in note.lower() for note in obs["notes"])
