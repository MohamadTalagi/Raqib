import json

import pytest

from policies.catalog import scan_tests
from policies.catalog.scan_tests import (
    ALL_SERVICE_TYPES,
    PIPELINE_PHASE_FINGERPRINTING,
    PIPELINE_PHASE_PQC_READINESS,
    PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    PIPELINE_PHASE_VULN_INTELLIGENCE,
    SCAN_CATALOG,
    configure_active_scopes,
    estimate_stage_a_timeout,
    estimate_stage_b_timeout,
    is_applicable,
    is_firmware_test,
    is_network_discovery_test,
    suggest_finding_and_confidence,
    total_usable_addresses,
)


@pytest.fixture(autouse=True)
def reset_active_scopes():
    """ACTIVE_SCOPES is process-global mutable state (see scan_tests.py's own
    docstring) - reset after every test so a test exercising
    configure_active_scopes() can't leak its configuration into whatever
    test runs next in this same pytest process."""
    yield
    configure_active_scopes(["172.30.0.0/24"])

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


def test_parse_tls_observations_reports_supported_tls_versions_from_the_probe_block():
    # Real shape tls_cert_check.py's 3rd phase prints: a modern-only server
    # that has TLSv1/1.1 genuinely disabled and only accepts 1.2/1.3.
    output = (
        "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nDONE\n"
        "notAfter=Jul  8 00:00:00 2036 GMT\n"
        "PROTOCOL_PROBE_START\n"
        "TLSv1=rejected\n"
        "TLSv1.1=rejected\n"
        "TLSv1.2=accepted\n"
        "TLSv1.3=accepted\n"
        "PROTOCOL_PROBE_END\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["protocol_probe"] == {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}
    assert sorted(obs["supported_tls_versions"]) == ["TLSv1.2", "TLSv1.3"]
    assert obs["deprecated_tls_versions_supported"] is False


def test_parse_tls_observations_flags_a_deprecated_version_confirmed_accepted():
    # A server that negotiates TLSv1.3 by default but still accepts a forced
    # TLSv1.1 handshake - the exact "not just left unused, must be disabled"
    # scenario the brief's "supported TLS versions" check is meant to catch.
    output = (
        "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nDONE\n"
        "notAfter=Jul  8 00:00:00 2036 GMT\n"
        "PROTOCOL_PROBE_START\n"
        "TLSv1=rejected\n"
        "TLSv1.1=accepted\n"
        "TLSv1.2=accepted\n"
        "TLSv1.3=accepted\n"
        "PROTOCOL_PROBE_END\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["deprecated_tls_versions_supported"] is True
    assert "TLSv1.1" in obs["supported_tls_versions"]
    assert any("forced handshake at a deprecated protocol version" in n for n in obs["notes"])


def test_parse_tls_observations_never_guesses_an_untestable_protocol_version():
    # This scanning host's own OpenSSL build refuses to offer TLSv1/1.1 at
    # all (confirmed live against the real auditor-worker image) - that must
    # surface as "unknown", never as a guessed accepted/rejected value.
    output = (
        "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nDONE\n"
        "notAfter=Jul  8 00:00:00 2036 GMT\n"
        "PROTOCOL_PROBE_START\n"
        "TLSv1=untestable\n"
        "TLSv1.1=untestable\n"
        "TLSv1.2=accepted\n"
        "TLSv1.3=accepted\n"
        "PROTOCOL_PROBE_END\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    assert obs["protocol_probe"]["TLSv1"] is None
    assert obs["protocol_probe"]["TLSv1.1"] is None
    assert "TLSv1" not in obs["supported_tls_versions"]
    assert obs["deprecated_tls_versions_supported"] is False
    assert any("not confirmed absent" in n for n in obs["notes"])


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
    # The static table isn't cross-referenced against KEV - None ("not
    # checked here"), never a guessed 0.
    assert openssl_pkg["kev_listed_count"] is None


def test_parse_fw_manifest_observations_when_absent():
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, "manifest_present=False\npackages=\n")
    assert obs["manifest_present"] is False
    assert obs["packages"] == []
    assert obs["notes"]


def test_parse_fw_manifest_observations_prefers_grype_result_when_present():
    # A canned Grype match for openssl - real CVE data from the live spike,
    # deliberately different in shape/count from the static table's 2 entries
    # so the test proves Grype's result wins, not just that both agree.
    grype_result = json.dumps([
        {
            "package": "openssl", "version": "1.0.1e", "id": "CVE-2014-0160",
            "severity": "High", "cvss": 7.5, "fix_state": "fixed",
            "fix_versions": ["1.0.1g"], "summary": "Heartbleed",
        },
        {
            "package": "openssl", "version": "1.0.1e", "id": "CVE-2016-6304",
            "severity": "High", "cvss": 7.5, "fix_state": "fixed",
            "fix_versions": ["1.0.2i"], "summary": "OOB write via OCSP status request",
        },
    ])
    output = f"manifest_present=True\npackages=openssl:1.0.1e\ngrype_result={grype_result}\n"
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, output)
    openssl_pkg = obs["packages"][0]
    assert {c["id"] for c in openssl_pkg["cves"]} == {"CVE-2014-0160", "CVE-2016-6304"}
    assert openssl_pkg["patched_version"] == "1.0.1g"
    assert openssl_pkg["outdated"] is True


def test_parse_fw_manifest_observations_surfaces_kev_listing_and_sorts_it_first():
    # CVE-2014-0160 (Heartbleed) is genuinely on CISA's real KEV catalog,
    # confirmed live - a lower-CVSS KEV-listed CVE must still sort ahead of
    # a higher-CVSS non-KEV one, since confirmed exploitation outranks score.
    grype_result = json.dumps([
        {
            "package": "openssl", "version": "1.0.1e", "id": "CVE-9999-0001",
            "severity": "Critical", "cvss": 9.8, "fix_state": "unknown", "fix_versions": [],
            "summary": "Higher CVSS, not KEV-listed", "kev_listed": False, "kev_date_added": None,
        },
        {
            "package": "openssl", "version": "1.0.1e", "id": "CVE-2014-0160",
            "severity": "High", "cvss": 7.5, "fix_state": "fixed", "fix_versions": ["1.0.1g"],
            "summary": "Heartbleed", "kev_listed": True, "kev_date_added": "2022-03-25",
        },
    ])
    output = f"manifest_present=True\npackages=openssl:1.0.1e\ngrype_result={grype_result}\n"
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, output)
    openssl_pkg = obs["packages"][0]
    assert openssl_pkg["kev_listed_count"] == 1
    assert openssl_pkg["cves"][0]["id"] == "CVE-2014-0160"  # KEV-listed sorts first despite lower CVSS
    assert openssl_pkg["cves"][0]["kev_date_added"] == "2022-03-25"
    assert openssl_pkg["cves"][1]["kev_listed"] is False
    assert "Known Exploited Vulnerabilities" in openssl_pkg["notes"][0]


def test_parse_fw_manifest_observations_reports_clean_when_grype_ran_and_found_nothing():
    # "sqlite" isn't in the static reference table either - without the fix
    # this shipped for, an unmatched package would wrongly say "no local
    # reference data" even though Grype genuinely checked and found nothing.
    output = "manifest_present=True\npackages=sqlite:3.44.0\ngrype_result=[]\n"
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, output)
    pkg = obs["packages"][0]
    assert pkg["outdated"] is False
    assert pkg["cves"] == []
    assert pkg["kev_listed_count"] == 0
    assert "No CVEs found" in pkg["notes"][0]


def test_parse_fw_manifest_observations_falls_back_to_static_table_when_grype_did_not_run():
    # No grype_result line at all (binary missing / DB not initialized) -
    # must reproduce today's exact static-table behavior, zero regression.
    output = "manifest_present=True\npackages=busybox:1.19.4\n"
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, output)
    pkg = obs["packages"][0]
    assert pkg["outdated"] is True
    assert pkg["latest_known_version"] == "1.36.x"


def test_parse_fw_manifest_observations_captures_db_freshness_metadata():
    grype_result = json.dumps([
        {"package": "openssl", "version": "1.0.1e", "id": "CVE-2014-0160", "severity": "High",
         "cvss": 7.5, "fix_state": "fixed", "fix_versions": ["1.0.1g"], "summary": "Heartbleed"},
    ])
    output = (
        "manifest_present=True\npackages=openssl:1.0.1e\n"
        f"grype_result={grype_result}\n"
        "grype_db_built_at=2026-03-09 00:31:20 +0000 UTC\n"
        "grype_db_checksum=sha256:a65e27aecbbb2cd6671f5da84c16db7e9c60f0114075e6ae9bcc71f466460a0c\n"
    )
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, output)
    assert obs["vuln_db_built_at"] == "2026-03-09 00:31:20 +0000 UTC"
    assert obs["vuln_db_checksum"] == "sha256:a65e27aecbbb2cd6671f5da84c16db7e9c60f0114075e6ae9bcc71f466460a0c"


def test_parse_fw_manifest_observations_omits_freshness_fields_when_grype_did_not_run():
    output = "manifest_present=True\npackages=busybox:1.19.4\n"
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, output)
    assert "vuln_db_built_at" not in obs
    assert "vuln_db_checksum" not in obs


def test_parse_fw_manifest_observations_static_table_wins_when_grype_has_no_entry_for_it():
    # Grype ran (so unmatched packages default to "clean") but this
    # particular package genuinely wasn't in the batch - busybox's curated
    # static entry must still be used, not a false "clean" result.
    other_grype_result = json.dumps([
        {"package": "openssl", "version": "1.0.1e", "id": "CVE-2014-0160", "severity": "High",
         "cvss": 7.5, "fix_state": "fixed", "fix_versions": ["1.0.1g"], "summary": "Heartbleed"},
    ])
    output = f"manifest_present=True\npackages=busybox:1.19.4\ngrype_result={other_grype_result}\n"
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](FIRMWARE_TARGET, output)
    pkg = obs["packages"][0]
    assert pkg["outdated"] is True
    assert pkg["latest_known_version"] == "1.36.x"


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
    # /24, so the scan reliably finishes and every open port found is one
    # the classifier actually knows how to interpret.
    assert "-p" in command
    ports_arg = command[command.index("-p") + 1]
    assert set(ports_arg.split(",")) == {
        "22", "23", "80", "443", "1883", "8883", "502", "554",
    }


def test_network_discovery_command_is_tuned_gentle_for_resource_constrained_devices():
    # This is an IoT environment - real devices can have weak network stacks
    # that struggle under aggressive scanning. -T4 (Aggressive) and --open
    # were both replaced after live verification surfaced two real issues:
    # -T4 assumes "a reasonably fast and reliable network" (not a safe
    # assumption for constrained IoT gear), and --open silently omitted live
    # hosts with none of the signature ports open (docs/errors/029),
    # collapsing the "unknown" classification into dead code.
    command = SCAN_CATALOG["TEST-NET-DISCOVERY"]["build_command"](DISCOVERY_TARGET)
    assert "-T4" not in command
    assert "--open" not in command
    assert "-T3" in command
    assert "--max-rate" in command
    assert command[command.index("--max-rate") + 1] == "50"
    assert "--version-intensity" in command
    assert command[command.index("--version-intensity") + 1] == "2"


def test_network_discovery_has_a_longer_timeout_than_the_default():
    # The gentler timing trades a little more time for going easier on
    # constrained devices - it needs real headroom above job_runner.py's
    # default 30s, not the same budget as a fast single-host test.
    assert SCAN_CATALOG["TEST-NET-DISCOVERY"]["timeout_seconds"] > 30


def test_configure_active_scopes_targets_every_configured_subnet():
    configure_active_scopes(["172.30.0.0/24", "10.4.0.0/24"])
    command = SCAN_CATALOG["TEST-NET-DISCOVERY"]["build_command"](DISCOVERY_TARGET)
    assert "172.30.0.0/24" in command
    assert "10.4.0.0/24" in command
    # nmap takes every scope as its own argv element, not one joined string.
    assert command[-2:] == ["172.30.0.0/24", "10.4.0.0/24"]


def test_configure_active_scopes_replaces_wholesale_not_additively():
    configure_active_scopes(["172.30.0.0/24"])
    configure_active_scopes(["10.4.0.0/24"])
    command = SCAN_CATALOG["TEST-NET-DISCOVERY"]["build_command"](DISCOVERY_TARGET)
    assert "172.30.0.0/24" not in command
    assert "10.4.0.0/24" in command


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
    assert obs["subnets"] == ["172.30.0.0/24"]
    assert len(obs["hosts"]) == 1
    host = obs["hosts"][0]
    assert host["ip"] == "172.30.0.5"
    assert host["hostname"] == "device-insecure"
    assert host["open_ports"] == [23, 80]
    assert host["classification"] == "iot_device"
    assert host["confidence"] == "high"
    assert obs["iot_device_count"] == 1


def test_parse_network_discovery_reports_every_configured_subnet():
    configure_active_scopes(["172.30.0.0/24", "10.4.0.0/24"])
    output = _discovery_output(
        "Nmap scan report for device-insecure (172.30.0.5)\nHost is up.\n\n"
        "PORT     STATE SERVICE VERSION\n80/tcp   open  http\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert obs["subnets"] == ["172.30.0.0/24", "10.4.0.0/24"]
    assert "10.4.0.0/24" in obs["notes"][0]


def test_parse_network_discovery_classifies_mqtt_only_host_as_iot():
    output = _discovery_output(
        "Nmap scan report for mqtt-broker-insecure (172.30.0.6)\n"
        "Host is up (0.00010s latency).\n\n"
        "PORT     STATE SERVICE VERSION\n"
        "1883/tcp open  mqtt\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert obs["hosts"][0]["classification"] == "iot_device"


def test_parse_network_discovery_classifies_telnet_only_host_as_uncertain_medium_confidence():
    # Telnet alone is a generic remote-administration signature shared by
    # plenty of non-IoT network appliances - this must not be asserted as a
    # confident IoT classification. But Telnet is still a stronger
    # legacy-IoT/appliance signal than SSH (ordinary modern hosts rarely
    # enable it), so it earns "medium" confidence within the "uncertain"
    # bucket, not the same "low" confidence an SSH-only host gets.
    output = _discovery_output(
        "Nmap scan report for telnet-sim (172.30.0.9)\n"
        "Host is up (0.00010s latency).\n\n"
        "PORT     STATE SERVICE VERSION\n"
        "23/tcp   open  telnet\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    host = obs["hosts"][0]
    assert host["classification"] == "uncertain"
    assert host["confidence"] == "medium"
    assert "Telnet" in host["rationale"]
    assert obs["uncertain_count"] == 1
    assert obs["iot_device_count"] == 0
    assert any("uncertain" in note.lower() for note in obs["notes"])


def test_parse_network_discovery_classifies_ssh_only_host_as_uncertain_low_confidence():
    # SSH alone (no Telnet) is ubiquitous on non-IoT network gear too - this
    # must stay at "low" confidence, not be upgraded like a Telnet hit.
    output = _discovery_output(
        "Nmap scan report for jump-host (172.30.0.10)\n"
        "Host is up (0.00010s latency).\n\n"
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    host = obs["hosts"][0]
    assert host["classification"] == "uncertain"
    assert host["confidence"] == "low"
    assert "SSH" in host["rationale"]
    assert "stronger" not in host["rationale"]
    assert obs["uncertain_count"] == 1
    assert obs["iot_device_count"] == 0


def test_parse_network_discovery_classifies_telnet_and_ssh_host_as_uncertain_medium_confidence():
    # Telnet's presence should drive the confidence tier even when SSH is
    # also open on the same host - Telnet is the stronger signal, so it must
    # not be diluted back down to "low" just because SSH is also present.
    output = _discovery_output(
        "Nmap scan report for legacy-gear (172.30.0.11)\n"
        "Host is up (0.00010s latency).\n\n"
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh\n"
        "23/tcp   open  telnet\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    host = obs["hosts"][0]
    assert host["classification"] == "uncertain"
    assert host["confidence"] == "medium"
    assert "Telnet" in host["rationale"]
    assert "alongside SSH" in host["rationale"]


def test_parse_network_discovery_extracts_mac_address_from_a_real_shaped_block():
    # Real captured shape from this project's own committed evidence,
    # document-store/raw/EV-2026-07-23-0001.txt (a real TEST-NET-DISCOVERY
    # run against the real lab) - not an invented fixture.
    output = _discovery_output(
        "Nmap scan report for kaust-iot-lab-device-partial-1.kaust-iot-lab_audit-network (172.30.0.2)\n"
        "Host is up (0.000032s latency).\n"
        "Not shown: 5 closed tcp ports (reset)\n"
        "PORT    STATE SERVICE   VERSION\n"
        "443/tcp open  ssl/https\n"
        "MAC Address: E6:4D:1A:E6:45:D7 (Unknown)\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    host = obs["hosts"][0]
    assert host["mac_address"] == "E6:4D:1A:E6:45:D7"
    # nmap's own bundled guess was "Unknown" (a Docker virtual MAC has no
    # real registry entry) - normalized to None, not surfaced as a fake
    # vendor name.
    assert host["mac_vendor"] is None
    assert host["mac_vendor_source"] is None


def test_parse_network_discovery_surfaces_nmaps_own_bundled_vendor_guess_when_present():
    output = _discovery_output(
        "Nmap scan report for some-appliance (172.30.0.20)\n"
        "Host is up (0.00010s latency).\n\n"
        "PORT     STATE SERVICE VERSION\n"
        "80/tcp   open  http\n"
        "MAC Address: AC:DE:48:00:11:22 (Some Real Vendor Inc.)\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    host = obs["hosts"][0]
    assert host["mac_address"] == "AC:DE:48:00:11:22"
    assert host["mac_vendor"] == "Some Real Vendor Inc."
    assert host["mac_vendor_source"] == "nmap_bundled"


def test_parse_network_discovery_leaves_mac_fields_none_when_nmap_has_no_mac_line():
    # Not every host block has a MAC Address line - nmap only prints one
    # when its own ARP-based discovery resolved the host on a
    # directly-attached L2 segment (e.g. a routed/non-local scope).
    output = _discovery_output(
        "Nmap scan report for 172.30.0.42\nHost is up (0.00010s latency).\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    host = obs["hosts"][0]
    assert host["mac_address"] is None
    assert host["mac_vendor"] is None
    assert host["mac_vendor_source"] is None


# Real captured shape from a live run of this exact command against this
# project's own device-router-gw fixture (2026-08-03), confirmed end to end:
# a real M-SEARCH multicast response, followed by a real fetch of
# device-router-gw's own /description.xml. Not invented from nmap's docs
# alone - this project's own standing discipline.
UPNP_PRESCAN_SECTION = (
    "Pre-scan script results:\n"
    "| broadcast-upnp-info: \n"
    "|   239.255.255.250\n"
    "|       Server: Linux/1.0 UPnP/1.0 NetCore/NC-WR1200\n"
    "|       Location: http://172.30.0.13:80/description.xml\n"
    "|         Webserver: uvicorn\n"
    "|         Name: NetCore NC-WR1200\n"
    "|         Manufacturer: NetCore\n"
    "|         Model Descr: NetCore NC-WR1200 residential gateway\n"
    "|         Model Name: NC-WR1200\n"
    "|_        Model Version: 1\n"
)


def test_parse_network_discovery_folds_upnp_broadcast_into_an_existing_host():
    # device-router-gw already has a real TCP-signature host block (port 80)
    # in this same scan - the broadcast signal must fold into that existing
    # entry, not create a duplicate.
    output = _discovery_output(
        UPNP_PRESCAN_SECTION,
        "Nmap scan report for kaust-iot-lab-device-router-gw-1.kaust-iot-lab_audit-network (172.30.0.13)\n"
        "Host is up (0.000097s latency).\n\n"
        "PORT     STATE  SERVICE     VERSION\n"
        "80/tcp   open   http        Uvicorn\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert len(obs["hosts"]) == 1
    host = obs["hosts"][0]
    assert host["ip"] == "172.30.0.13"
    assert host["classification"] == "iot_device"
    assert host["discovery_signals"] == ["port_scan", "upnp_broadcast"]


def test_parse_network_discovery_creates_a_new_host_for_a_upnp_only_udp_device():
    # The real gap this closes: a device with NO TCP signature port open at
    # all (never appears in any "Nmap scan report for" block) must still
    # surface as a real iot_device entry once it answers the broadcast query.
    output = _discovery_output(UPNP_PRESCAN_SECTION)
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert len(obs["hosts"]) == 1
    host = obs["hosts"][0]
    assert host["ip"] == "172.30.0.13"
    assert host["hostname"] is None
    assert host["open_ports"] == []
    assert host["classification"] == "iot_device"
    assert host["confidence"] == "high"
    assert "UPnP/SSDP" in host["rationale"]
    assert host["discovery_signals"] == ["upnp_broadcast"]
    assert obs["iot_device_count"] == 1
    assert any("UDP-only" in note for note in obs["notes"])


# nmap's own documented output shape for broadcast-dns-service-discovery
# (docs/known-limitations.md notes this project has no fixture that
# implements the DNS-SD PTR-enumeration convention this script queries for,
# so this shape is not a positive live capture from this lab - unlike the
# UPnP fixture above).
MDNS_PRESCAN_SECTION = (
    "Pre-scan script results:\n"
    "| broadcast-dns-service-discovery:\n"
    "|   172.30.0.7\n"
    "|     _services._dns-sd._udp.local\n"
    "|_      Address=172.30.0.7\n"
)


def test_parse_network_discovery_folds_mdns_broadcast_into_an_existing_host():
    output = _discovery_output(
        MDNS_PRESCAN_SECTION,
        "Nmap scan report for kaust-iot-lab-device-speaker-1.kaust-iot-lab_audit-network (172.30.0.7)\n"
        "Host is up (0.000081s latency).\n\n"
        "PORT     STATE  SERVICE     VERSION\n"
        "80/tcp   open   http        Uvicorn\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert len(obs["hosts"]) == 1
    host = obs["hosts"][0]
    assert host["discovery_signals"] == ["port_scan", "mdns_broadcast"]


def test_parse_network_discovery_creates_a_new_host_for_a_mdns_only_udp_device():
    output = _discovery_output(MDNS_PRESCAN_SECTION)
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert len(obs["hosts"]) == 1
    host = obs["hosts"][0]
    assert host["ip"] == "172.30.0.7"
    assert host["classification"] == "iot_device"
    assert host["confidence"] == "high"
    assert "mDNS" in host["rationale"]
    assert host["discovery_signals"] == ["mdns_broadcast"]


def test_parse_network_discovery_when_no_broadcast_script_produced_output():
    # A real, honest, common outcome: no device on this scope answered
    # either broadcast query at all - must not crash or fabricate a host.
    output = _discovery_output(
        "Nmap scan report for device-insecure (172.30.0.5)\n"
        "Host is up (0.00012s latency).\n\n"
        "PORT     STATE SERVICE VERSION\n"
        "80/tcp   open  http    Werkzeug httpd 2.0.1 (Python 3.9.7)\n\n",
    )
    obs = SCAN_CATALOG["TEST-NET-DISCOVERY"]["parse_observations"](DISCOVERY_TARGET, output)
    assert len(obs["hosts"]) == 1
    assert obs["hosts"][0]["discovery_signals"] == ["port_scan"]


def test_network_discovery_command_includes_the_broadcast_discovery_scripts():
    command = SCAN_CATALOG["TEST-NET-DISCOVERY"]["build_command"](DISCOVERY_TARGET)
    assert "--script" in command
    script_arg = command[command.index("--script") + 1]
    assert set(script_arg.split(",")) == {"broadcast-upnp-info", "broadcast-dns-service-discovery"}


# --- Two-phase discovery (subnet-size scalability) --------------------------


def test_total_usable_addresses_excludes_network_and_broadcast():
    assert total_usable_addresses(["172.30.0.0/24"]) == 254


def test_total_usable_addresses_matches_a_16_worth_65534():
    # The exact number this platform's own /16 scope ceiling advertises
    # (device_validation.MIN_SCOPE_PREFIX_LENGTH = 16).
    assert total_usable_addresses(["10.0.0.0/16"]) == 65534


def test_total_usable_addresses_sums_multiple_configured_scopes():
    assert total_usable_addresses(["172.30.0.0/24", "10.4.0.0/24"]) == 254 + 254


def test_total_usable_addresses_floors_at_one_for_a_tiny_scope():
    assert total_usable_addresses(["10.0.0.0/31"]) >= 1


def test_estimate_stage_a_timeout_scales_with_scope_size():
    small = estimate_stage_a_timeout(["172.30.0.0/24"])
    large = estimate_stage_a_timeout(["10.0.0.0/16"])
    assert small < large
    assert small == int(scan_tests.STAGE_A_BASE_SECONDS + scan_tests.STAGE_A_PER_ADDRESS_SECONDS * 254)


def test_estimate_stage_a_timeout_is_capped():
    huge = estimate_stage_a_timeout(["10.0.0.0/8", "172.16.0.0/12"])
    assert huge == scan_tests.STAGE_A_MAX_SECONDS


def test_estimate_stage_b_timeout_scales_with_live_host_count():
    small = estimate_stage_b_timeout(1)
    large = estimate_stage_b_timeout(50)
    assert small < large
    assert small == scan_tests.STAGE_B_BASE_SECONDS + scan_tests.STAGE_B_PER_HOST_SECONDS


def test_estimate_stage_b_timeout_is_capped():
    huge = estimate_stage_b_timeout(100_000)
    assert huge == scan_tests.STAGE_B_MAX_SECONDS


def test_stage_a_command_is_a_fast_ping_sweep_no_ports():
    configure_active_scopes(["172.30.0.0/24"])
    command = scan_tests._network_discovery_stage_a_command()
    assert command[0] == "nmap"
    assert "-sn" in command
    assert "-p" not in command
    assert "-sV" not in command
    # Gentle-scanning posture still applies to Stage A - speed comes from
    # skipping service probing, not from a higher packet rate.
    assert "--max-rate" in command
    assert command[command.index("--max-rate") + 1] == "50"
    assert "172.30.0.0/24" in command


def test_parse_stage_a_live_hosts_extracts_bare_ips():
    output = (
        "Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-03 00:00 UTC\n"
        "Nmap scan report for 172.30.0.5\n"
        "Host is up (0.000073s latency).\n"
        "MAC Address: 66:4A:D6:02:44:E6 (Unknown)\n"
        "Nmap scan report for 172.30.0.13\n"
        "Host is up (0.000097s latency).\n"
        "Nmap done: 256 IP addresses (2 hosts up) scanned in 10.96 seconds\n"
    )
    assert scan_tests._parse_stage_a_live_hosts(output) == ["172.30.0.5", "172.30.0.13"]


def test_parse_stage_a_live_hosts_returns_empty_list_when_nothing_is_up():
    output = (
        "Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-03 00:00 UTC\n"
        "Nmap done: 256 IP addresses (0 hosts up) scanned in 10.96 seconds\n"
    )
    assert scan_tests._parse_stage_a_live_hosts(output) == []


def test_stage_b_command_targets_explicit_live_hosts_not_a_cidr():
    command = scan_tests._network_discovery_stage_b_command(["172.30.0.5", "172.30.0.13"])
    assert command[0] == "nmap"
    assert "-sV" in command
    assert "172.30.0.5" in command
    assert "172.30.0.13" in command
    assert not any("/" in arg for arg in command)  # no CIDR anywhere
    # Carries the same port list, gentle tuning, and Task 3 broadcast
    # scripts as the single-stage command.
    assert "--script" in command
    script_arg = command[command.index("--script") + 1]
    assert set(script_arg.split(",")) == {"broadcast-upnp-info", "broadcast-dns-service-discovery"}


def test_stage_b_command_is_empty_for_no_live_hosts():
    # job_runner.py's own short-circuit means this should never actually be
    # called with an empty list, but the pure function itself must not
    # build a nonsensical bare "nmap" command with no targets at all.
    assert scan_tests._network_discovery_stage_b_command([]) == []


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


# --- suggest_finding_and_confidence ---

def test_suggested_finding_joins_the_notes():
    finding, _ = suggest_finding_and_confidence(
        "TEST-HTTP-HEADERS", {"notes": ["First sentence.", "Second sentence."]},
    )
    assert finding == "First sentence. Second sentence."


def test_suggested_finding_falls_back_when_there_are_no_notes():
    finding, _ = suggest_finding_and_confidence("TEST-HTTP-HEADERS", {"notes": []})
    assert finding == "No automated notes were recorded for this test."


def test_suggested_confidence_defaults_to_high_for_a_test_with_no_rule():
    # TEST-HTTP-HEADERS never registers a suggest_confidence function -
    # the safe default is "high", never a guessed-worse "medium"/"low".
    _, confidence = suggest_finding_and_confidence("TEST-HTTP-HEADERS", {"notes": []})
    assert confidence == "high"


def test_suggested_confidence_default_creds_is_high_when_every_pair_was_tried():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"](
        HTTP_TARGET, _chained_login_output(set()),
    )
    assert obs["chunks_received"] == 10
    _, confidence = suggest_finding_and_confidence("TEST-AUTH-DEFAULT-CREDS", obs)
    assert confidence == "high"


def test_suggested_confidence_default_creds_is_medium_when_the_chain_was_cut_short():
    obs = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["parse_observations"](
        HTTP_TARGET, _chained_login_output(set(), total=6),
    )
    assert obs["chunks_received"] == 6
    _, confidence = suggest_finding_and_confidence("TEST-AUTH-DEFAULT-CREDS", obs)
    assert confidence == "medium"


def test_suggested_confidence_session_is_high_with_both_responses():
    output = (
        "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\n\r\n{}"
        "HTTP/1.1 401 Unauthorized\r\n\r\n"
    )
    obs = SCAN_CATALOG["TEST-AUTH-SESSION"]["parse_observations"](HTTP_TARGET, output)
    assert obs["chunks_received"] == 2
    _, confidence = suggest_finding_and_confidence("TEST-AUTH-SESSION", obs)
    assert confidence == "high"


def test_suggested_confidence_session_is_medium_when_the_dashboard_response_never_came_back():
    output = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\n\r\n{}"
    obs = SCAN_CATALOG["TEST-AUTH-SESSION"]["parse_observations"](HTTP_TARGET, output)
    assert obs["chunks_received"] == 1
    _, confidence = suggest_finding_and_confidence("TEST-AUTH-SESSION", obs)
    assert confidence == "medium"


def test_suggested_confidence_http_inspect_is_medium_with_no_server_header():
    obs = SCAN_CATALOG["TEST-NET-HTTP-INSPECT"]["parse_observations"](HTTP_TARGET, "HTTP/1.1 200 OK\r\n")
    assert obs["server_banner"] is None
    _, confidence = suggest_finding_and_confidence("TEST-NET-HTTP-INSPECT", obs)
    assert confidence == "medium"


def test_suggested_confidence_http_inspect_is_high_with_a_real_banner():
    obs = SCAN_CATALOG["TEST-NET-HTTP-INSPECT"]["parse_observations"](
        HTTP_TARGET, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nHTTP_VERSION:1.1\r\n",
    )
    assert obs["server_banner"] is not None
    _, confidence = suggest_finding_and_confidence("TEST-NET-HTTP-INSPECT", obs)
    assert confidence == "high"


def test_suggested_confidence_tls_is_medium_when_a_protocol_version_is_untestable():
    output = (
        "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nDONE\n"
        "notAfter=Jul  8 00:00:00 2036 GMT\n"
        "PROTOCOL_PROBE_START\nTLSv1=untestable\nTLSv1.1=untestable\n"
        "TLSv1.2=accepted\nTLSv1.3=accepted\nPROTOCOL_PROBE_END\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    _, confidence = suggest_finding_and_confidence("TEST-TLS-CONFIG", obs)
    assert confidence == "medium"


def test_suggested_confidence_tls_is_high_when_every_version_was_confirmed():
    output = (
        "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nDONE\n"
        "notAfter=Jul  8 00:00:00 2036 GMT\n"
        "PROTOCOL_PROBE_START\nTLSv1=rejected\nTLSv1.1=rejected\n"
        "TLSv1.2=accepted\nTLSv1.3=accepted\nPROTOCOL_PROBE_END\n"
    )
    obs = SCAN_CATALOG["TEST-TLS-CONFIG"]["parse_observations"](HTTPS_TARGET, output)
    _, confidence = suggest_finding_and_confidence("TEST-TLS-CONFIG", obs)
    assert confidence == "high"


def test_suggested_confidence_fw_manifest_is_medium_when_grype_did_not_run():
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"](
        {"device_id": "device-insecure"}, "manifest_present=True\npackages=openssl:1.0.1e\n",
    )
    assert "vuln_db_built_at" not in obs
    _, confidence = suggest_finding_and_confidence("TEST-FW-MANIFEST", obs)
    assert confidence == "medium"


def test_suggested_confidence_fw_manifest_is_high_when_grype_ran():
    output = (
        "manifest_present=True\npackages=openssl:1.0.1e\n"
        "grype_result=[]\n"
        "grype_db_built_at=2026-07-01T00:00:00Z\ngrype_db_checksum=abc123\n"
    )
    obs = SCAN_CATALOG["TEST-FW-MANIFEST"]["parse_observations"]({"device_id": "device-insecure"}, output)
    assert obs["vuln_db_built_at"] == "2026-07-01T00:00:00Z"
    _, confidence = suggest_finding_and_confidence("TEST-FW-MANIFEST", obs)
    assert confidence == "high"


# --- dashboard-overhaul pipeline_phase tagging ---

def test_every_test_id_has_the_expected_pipeline_phase():
    # The full, explicit mapping (Week 1 dashboard-overhaul plan) - locked
    # down completely rather than spot-checked, since this is the one
    # source of truth the new Fingerprinting/SA-IOT Compliance/Vulnerability
    # Intelligence pages filter their test lists by.
    expected = {
        "TEST-NET-REACHABILITY": PIPELINE_PHASE_FINGERPRINTING,
        "TEST-NET-PORTSCAN": PIPELINE_PHASE_FINGERPRINTING,
        "TEST-NET-HTTP-INSPECT": PIPELINE_PHASE_FINGERPRINTING,
        "TEST-AUTH-DEFAULT-CREDS": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-HTTP-HEADERS": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-AUTH-ANON-ACCESS": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-AUTH-SESSION": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-ADMIN-UNAUTH": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-MQTT-OPEN": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-TLS-CONFIG": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-NET-PKTCAPTURE": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-FW-VERSION": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-FW-CONFIG": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-FW-SECRETS": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-FW-APIKEY": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-FW-CERTKEY": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-FW-UPDATESCRIPT": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-FW-MANIFEST": PIPELINE_PHASE_VULN_INTELLIGENCE,
        "TEST-NET-DISCOVERY": None,
        "TEST-MODBUS-PROBE": PIPELINE_PHASE_FINGERPRINTING,
        "TEST-RTSP-PROBE": PIPELINE_PHASE_FINGERPRINTING,
        "TEST-UPNP-PROBE": PIPELINE_PHASE_FINGERPRINTING,
        "TEST-MDNS-PROBE": PIPELINE_PHASE_FINGERPRINTING,
        "TEST-PHYSICAL-TAMPER-STATUS": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-TLS-CLIENT-AUTH": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-SECURITY-LOG-ENDPOINT": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-MONITORING-ENDPOINT": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        "TEST-PQC-TLS-HANDSHAKE": PIPELINE_PHASE_PQC_READINESS,
        "TEST-PQC-FIRMWARE-CRYPTO": PIPELINE_PHASE_PQC_READINESS,
    }
    assert set(expected) == set(SCAN_CATALOG)  # catches a new test added with no phase decision made
    for test_id, phase in expected.items():
        assert SCAN_CATALOG[test_id].get("pipeline_phase") == phase, test_id


MODBUS_TARGET = {
    "device_id": "device-plc-gateway", "host": "device-plc-gateway",
    "service_type": "modbus", "port": 502,
}
RTSP_TARGET = {
    "device_id": "device-nvr", "host": "device-nvr",
    "service_type": "rtsp", "port": 554,
}
UPNP_TARGET = {
    "device_id": "device-router-gw", "host": "device-router-gw",
    "service_type": "upnp", "port": 1900,
}
MDNS_TARGET = {
    "device_id": "device-speaker", "host": "device-speaker",
    "service_type": "mdns", "port": 5353,
}

MODBUS_DISCOVER_OUTPUT = """PORT    STATE SERVICE
502/tcp open  modbus

Host script results:
| modbus-discover:
|_  sid 0x1: unknown
"""

RTSP_METHODS_OUTPUT = """PORT    STATE SERVICE
554/tcp open  rtsp
|_rtsp-methods: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN
"""

UPNP_PROBE_OUTPUT = (
    "reachable=True\n"
    "response_start\n"
    "HTTP/1.1 200 OK\r\n"
    "SERVER: Linux/1.0 UPnP/1.0 NetCore/NC-WR1200\r\n"
    "ST: upnp:rootdevice\r\n"
    "\n"
    "response_end\n"
)


def test_modbus_probe_command_targets_the_registered_port():
    from policies.catalog.scan_tests import _modbus_probe_command

    command = _modbus_probe_command(MODBUS_TARGET)
    assert command == [
        "nmap", "--script-timeout", "10s", "--script", "modbus-discover",
        "-p", "502", "device-plc-gateway",
    ]


def test_modbus_probe_parses_unauthenticated_response():
    from policies.catalog.scan_tests import _parse_modbus_probe_observations

    observations = _parse_modbus_probe_observations(MODBUS_TARGET, MODBUS_DISCOVER_OUTPUT)
    assert observations["modbus_port_open"] is True
    assert observations["script_output"]
    assert "no native authentication" in observations["notes"][0]


def test_modbus_probe_reports_closed_port_honestly():
    from policies.catalog.scan_tests import _parse_modbus_probe_observations

    observations = _parse_modbus_probe_observations(MODBUS_TARGET, "502/tcp closed modbus\n")
    assert observations["modbus_port_open"] is False


def test_rtsp_probe_command_targets_the_registered_port():
    from policies.catalog.scan_tests import _rtsp_probe_command

    command = _rtsp_probe_command(RTSP_TARGET)
    assert command == [
        "nmap", "--script-timeout", "10s", "--script", "rtsp-methods",
        "-p", "554", "device-nvr",
    ]


def test_rtsp_probe_parses_unauthenticated_stream_access():
    from policies.catalog.scan_tests import _parse_rtsp_probe_observations

    observations = _parse_rtsp_probe_observations(RTSP_TARGET, RTSP_METHODS_OUTPUT)
    assert observations["rtsp_port_open"] is True
    assert observations["unauthenticated_stream_access"] is True
    assert "DESCRIBE" in observations["methods"]


def test_upnp_probe_command_uses_the_worker_probe_script():
    from policies.catalog.scan_tests import UPNP_PROBE_SCRIPT, _upnp_probe_command

    command = _upnp_probe_command(UPNP_TARGET)
    assert command == ["python3", UPNP_PROBE_SCRIPT, "device-router-gw", "1900"]


def test_upnp_probe_parses_unauthenticated_ssdp_response():
    from policies.catalog.scan_tests import _parse_upnp_probe_observations

    observations = _parse_upnp_probe_observations(UPNP_TARGET, UPNP_PROBE_OUTPUT)
    assert observations["upnp_reachable"] is True
    assert observations["server_banner"] == "Linux/1.0 UPnP/1.0 NetCore/NC-WR1200"


def test_upnp_probe_reports_no_response_honestly():
    from policies.catalog.scan_tests import _parse_upnp_probe_observations

    observations = _parse_upnp_probe_observations(UPNP_TARGET, "reachable=False\nerror=timed out\n")
    assert observations["upnp_reachable"] is False


def test_mdns_probe_command_uses_the_worker_probe_script():
    from policies.catalog.scan_tests import MDNS_PROBE_SCRIPT, _mdns_probe_command

    command = _mdns_probe_command(MDNS_TARGET)
    assert command == ["python3", MDNS_PROBE_SCRIPT, "device-speaker", "5353"]


def test_mdns_probe_decodes_the_txt_record_from_the_real_responder_wire_format():
    from policies.catalog.scan_tests import _parse_mdns_probe_observations

    # Real packet bytes produced by lab/devices/smart-speaker/app/mdns_server.py's
    # own _build_response(), hand-verified against that responder's wire format.
    header = (
        b"\x00\x00"  # ID
        b"\x84\x00"  # flags
        b"\x00\x00"  # QDCOUNT
        b"\x00\x01"  # ANCOUNT
        b"\x00\x00"  # NSCOUNT
        b"\x00\x00"  # ARCOUNT
    )
    name = b"\x0edevice-speaker\x05local\x00"
    txt_payload = b"vendor=VoxHome;model=VH-Speaker-2;voice_log_encrypted=false"
    rdata = bytes([len(txt_payload)]) + txt_payload
    packet = (
        header
        + name
        + b"\x00\x10\x00\x01\x00\x00\x00\x78"
        + len(rdata).to_bytes(2, "big")
        + rdata
    )
    output = f"reachable=True\nresponse_hex={packet.hex()}\n"

    observations = _parse_mdns_probe_observations(MDNS_TARGET, output)
    assert observations["mdns_reachable"] is True
    assert observations["txt_record"]["name"] == "device-speaker.local"
    assert observations["txt_record"]["txt"]["voice_log_encrypted"] == "false"


def test_mdns_probe_reports_no_response_honestly():
    from policies.catalog.scan_tests import _parse_mdns_probe_observations

    observations = _parse_mdns_probe_observations(MDNS_TARGET, "reachable=False\nerror=timed out\n")
    assert observations["mdns_reachable"] is False
    assert observations["txt_record"] is None


def test_tamper_status_command_hits_the_status_endpoint():
    from policies.catalog.scan_tests import _tamper_status_command

    command = _tamper_status_command(HTTP_TARGET)
    assert command[-1] == "http://device-insecure/api/status"


def test_tamper_status_parses_unwired_detection_honestly():
    from policies.catalog.scan_tests import _parse_tamper_status_observations

    output = '{"locked": true, "tamper_detected": false, "tamper_detection_wired": false}'
    observations = _parse_tamper_status_observations(HTTP_TARGET, output)
    assert observations["tamper_detection_wired"] is False
    assert "no hardware tamper-detection" in observations["notes"][0]


def test_tamper_status_reports_wired_detection():
    from policies.catalog.scan_tests import _parse_tamper_status_observations

    output = '{"locked": true, "tamper_detected": false, "tamper_detection_wired": true}'
    observations = _parse_tamper_status_observations(HTTP_TARGET, output)
    assert observations["tamper_detection_wired"] is True


def test_modbus_probe_is_only_applicable_to_modbus_service_type():
    assert is_applicable(MODBUS_TARGET, "TEST-MODBUS-PROBE")
    assert not is_applicable(HTTP_TARGET, "TEST-MODBUS-PROBE")


def test_rtsp_probe_is_only_applicable_to_rtsp_service_type():
    assert is_applicable(RTSP_TARGET, "TEST-RTSP-PROBE")
    assert not is_applicable(HTTP_TARGET, "TEST-RTSP-PROBE")


def test_upnp_probe_is_only_applicable_to_upnp_service_type():
    assert is_applicable(UPNP_TARGET, "TEST-UPNP-PROBE")
    assert not is_applicable(HTTP_TARGET, "TEST-UPNP-PROBE")


def test_mdns_probe_is_only_applicable_to_mdns_service_type():
    assert is_applicable(MDNS_TARGET, "TEST-MDNS-PROBE")
    assert not is_applicable(HTTP_TARGET, "TEST-MDNS-PROBE")


def test_tls_client_auth_command_uses_the_worker_probe_script():
    from policies.catalog.scan_tests import TLS_CLIENT_AUTH_CHECK_SCRIPT, _tls_client_auth_command

    command = _tls_client_auth_command(HTTPS_TARGET)
    assert command == ["python3", TLS_CLIENT_AUTH_CHECK_SCRIPT, "device-hardened", "443"]


def test_tls_client_auth_parses_a_real_certificate_request():
    from policies.catalog.scan_tests import _parse_tls_client_auth_observations

    output = "client_cert_requested=True"
    observations = _parse_tls_client_auth_observations(HTTPS_TARGET, output)
    assert observations["client_cert_requested"] is True
    assert "peer authentication is in place" in observations["notes"][0]


def test_tls_client_auth_parses_no_certificate_request_honestly():
    from policies.catalog.scan_tests import _parse_tls_client_auth_observations

    output = "client_cert_requested=False"
    observations = _parse_tls_client_auth_observations(HTTPS_TARGET, output)
    assert observations["client_cert_requested"] is False
    assert "no cryptographic peer authentication" in observations["notes"][0]


def test_pqc_tls_command_uses_the_worker_probe_script():
    from policies.catalog.scan_tests import PQC_READINESS_CHECK_SCRIPT, _pqc_tls_command

    command = _pqc_tls_command(HTTPS_TARGET)
    assert command == ["python3", PQC_READINESS_CHECK_SCRIPT, "device-hardened", "443"]


def test_pqc_tls_parses_a_real_hybrid_kem_and_classical_signature():
    from policies.catalog.scan_tests import _parse_pqc_tls_observations

    # Matches the real shape confirmed live against device-hardened in this
    # lab: hybrid KEM negotiated, but the cert is still classically signed.
    output = (
        "Negotiated TLS1.3 group: X25519MLKEM768\n"
        "cert_pem_found=True\n"
        "        Signature Algorithm: sha256WithRSAEncryption\n"
    )
    observations = _parse_pqc_tls_observations(HTTPS_TARGET, output)
    assert observations["negotiated_group"] == "X25519MLKEM768"
    assert observations["is_pqc_kem"] is True
    assert observations["cert_signature_algorithm"] == "sha256WithRSAEncryption"
    assert observations["is_pqc_signature"] is False
    assert observations["connection_error"] is False
    assert any("post-quantum signature algorithm" in n.lower() for n in observations["notes"])


def test_pqc_tls_parses_a_classical_only_kem_as_failing():
    from policies.catalog.scan_tests import _parse_pqc_tls_observations

    output = "Negotiated TLS1.3 group: X25519\ncert_pem_found=False\n"
    observations = _parse_pqc_tls_observations(HTTPS_TARGET, output)
    assert observations["is_pqc_kem"] is False
    assert observations["connection_error"] is False
    assert any("classical-only" in n for n in observations["notes"])


def test_pqc_tls_reports_connection_error_honestly_not_as_a_failure():
    from policies.catalog.scan_tests import _parse_pqc_tls_observations

    output = "BIO_connect:Connection refused\n"
    observations = _parse_pqc_tls_observations(HTTPS_TARGET, output)
    assert observations["connection_error"] is True
    assert observations["is_pqc_kem"] is None
    assert observations["is_pqc_signature"] is None
    assert any("could not complete a tls handshake" in n.lower() for n in observations["notes"])


def test_pqc_tls_recognizes_a_post_quantum_signature_algorithm():
    from policies.catalog.scan_tests import _parse_pqc_tls_observations

    output = (
        "Negotiated TLS1.3 group: X25519MLKEM768\n"
        "cert_pem_found=True\n"
        "        Signature Algorithm: id-ml-dsa-65\n"
    )
    observations = _parse_pqc_tls_observations(HTTPS_TARGET, output)
    assert observations["is_pqc_signature"] is True


def test_suggest_confidence_pqc_tls_is_medium_on_connection_error():
    from policies.catalog.scan_tests import _suggest_confidence_pqc_tls

    assert _suggest_confidence_pqc_tls({"connection_error": True}) == "medium"
    assert _suggest_confidence_pqc_tls({"connection_error": False}) == "high"


def test_pqc_firmware_command_uses_the_firmware_check_script_with_pqc_crypto_check():
    from policies.catalog.scan_tests import FIRMWARE_CHECK_SCRIPT, _firmware_command

    command = _firmware_command("pqc_crypto")(FIRMWARE_TARGET)
    assert command == ["python3", FIRMWARE_CHECK_SCRIPT, "device-insecure", "pqc_crypto"]


def test_parse_pqc_firmware_observations_flags_an_outdated_library():
    from policies.catalog.scan_tests import _parse_pqc_firmware_observations

    output = (
        "manifest_present=True\n"
        'pqc_results=[{"name": "openssl", "version": "1.0.1e", "pqc_status": "fail"}]\n'
    )
    observations = _parse_pqc_firmware_observations(FIRMWARE_TARGET, output)
    assert observations["manifest_present"] is True
    assert observations["packages"][0]["pqc_status"] == "fail"
    assert any("predates post-quantum support" in n for n in observations["notes"])


def test_parse_pqc_firmware_observations_passes_a_current_library():
    from policies.catalog.scan_tests import _parse_pqc_firmware_observations

    output = (
        "manifest_present=True\n"
        'pqc_results=[{"name": "openssl", "version": "3.5.6", "pqc_status": "pass"}]\n'
    )
    observations = _parse_pqc_firmware_observations(FIRMWARE_TARGET, output)
    assert any("supports post-quantum cryptography" in n for n in observations["notes"])


def test_parse_pqc_firmware_observations_is_honest_about_no_manifest():
    from policies.catalog.scan_tests import _parse_pqc_firmware_observations

    observations = _parse_pqc_firmware_observations(FIRMWARE_TARGET, "manifest_present=False\n")
    assert observations["manifest_present"] is False
    assert observations["packages"] == []
    assert any("not yet assessable" in n for n in observations["notes"])


def test_security_log_endpoint_command_chains_every_candidate_path():
    from policies.catalog.scan_tests import SECURITY_LOG_ENDPOINT_PATHS, _security_log_endpoint_command

    command = _security_log_endpoint_command(HTTP_TARGET)
    for path in SECURITY_LOG_ENDPOINT_PATHS:
        assert f"http://device-insecure{path}" in command


def test_security_log_endpoint_parses_a_found_path():
    from policies.catalog.scan_tests import _parse_security_log_endpoint_observations

    output = "/api/access-log 200\n/api/voice-log 404\n/api/logs 404\n"
    observations = _parse_security_log_endpoint_observations(HTTP_TARGET, output)
    assert observations["security_log_endpoint_present"] is True
    assert observations["found_paths"] == ["/api/access-log"]


def test_security_log_endpoint_reports_absence_honestly():
    from policies.catalog.scan_tests import _parse_security_log_endpoint_observations

    output = "/api/access-log 404\n/api/voice-log 404\n/api/logs 404\n"
    observations = _parse_security_log_endpoint_observations(HTTP_TARGET, output)
    assert observations["security_log_endpoint_present"] is False
    assert observations["found_paths"] == []


def test_monitoring_endpoint_command_chains_every_candidate_path():
    from policies.catalog.scan_tests import MONITORING_ENDPOINT_PATHS, _monitoring_endpoint_command

    command = _monitoring_endpoint_command(HTTP_TARGET)
    for path in MONITORING_ENDPOINT_PATHS:
        assert f"http://device-insecure{path}" in command


def test_monitoring_endpoint_parses_a_found_path():
    from policies.catalog.scan_tests import _parse_monitoring_endpoint_observations

    output = "/health 200\n/metrics 404\n/status 404\n"
    observations = _parse_monitoring_endpoint_observations(HTTP_TARGET, output)
    assert observations["monitoring_endpoint_present"] is True
    assert observations["found_paths"] == ["/health"]


def test_tls_client_auth_is_only_applicable_to_tls_service_types():
    assert is_applicable(HTTPS_TARGET, "TEST-TLS-CLIENT-AUTH")
    assert not is_applicable(MQTT_TARGET, "TEST-TLS-CLIENT-AUTH")


def test_security_log_and_monitoring_endpoints_are_applicable_to_http_service_types():
    assert is_applicable(HTTP_TARGET, "TEST-SECURITY-LOG-ENDPOINT")
    assert is_applicable(HTTP_TARGET, "TEST-MONITORING-ENDPOINT")
