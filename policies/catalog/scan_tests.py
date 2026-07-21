"""Whitelisted scan tests for the dashboard's live "Run Scan" feature.

Security boundary: test_id is validated against this fixed catalog, and the
target host/port is validated by device_validation (172.30.0.0/24 or a
container name, never infrastructure) on both the API and worker sides.
Commands are built as argv lists (never a shell string), so even a bypassed
validation has no shell-injection surface. auditor-api never executes a
command itself - it only ever creates/reads scan_jobs rows; auditor-worker is
the sole executor, and it re-validates before running anything.

Finding text is deliberately NOT produced here. Observations are simple,
mechanical parses of real tool output (port numbers, string matches) - the
same category of fact a human would read off the screen, just automated.
The security *interpretation* (the "finding") is still typed by a human in
the dashboard before evidence is recorded, matching the CLI-driven flow
this mirrors (record_evidence.py).

`category` groups tests for the dashboard's 3-section "Run Scan" picker:
"web-and-auth", "network-and-protocol", and "firmware". Firmware tests don't
target a live host:port - they inspect an uploaded archive keyed only by
device_id - so they carry `applicable_service_types=()` and are never matched
by the live-device gating in `is_applicable()`. `POST /scan-jobs` and
`job_runner.py` both special-case `is_firmware_test()` instead, skipping
service-type resolution entirely and checking the device's uploaded firmware
in its place. See `lab/auditor/worker/scan_scripts/firmware_check.py`.

TEST-ADMIN-UNAUTH, TEST-MQTT-OPEN and TEST-TLS-CONFIG are not new tests:
they were run manually per lab/auditor/worker/tests/run_catalog.md and
already have real evidence (document-store/evidence/EV-2026-07-08-0017,
-0019, -0020) and, for the latter two, existing NCA control bindings
(policies/controls/SA-IOT-004.yaml, SA-IOT-005.yaml on
observations.mqtt_tls / observations.weak_cipher). Wiring them in here
automates that gap - keep their established test_id and observation field
names exactly, or verdict recomputation silently stops matching them.
"""

import re

HTTP_SERVICE_TYPES = ("http", "https")
MQTT_SERVICE_TYPES = ("mqtt", "mqtts")
TLS_SERVICE_TYPES = ("https", "mqtts")
ALL_SERVICE_TYPES = ("http", "https", "mqtt", "mqtts", "telnet", "ssh")

DEFAULT_SCHEME_PORTS = {"http": 80, "https": 443}

CATEGORY_WEB_AUTH = "web-and-auth"
CATEGORY_NETWORK_PROTOCOL = "network-and-protocol"
CATEGORY_FIRMWARE = "firmware"

FIRMWARE_CHECK_SCRIPT = "/work/lab/auditor/worker/scan_scripts/firmware_check.py"


def _scheme_for(target: dict) -> str:
    return "https" if target["service_type"] == "https" else "http"


def _authority_for(target: dict, scheme: str) -> str:
    """Build the URL authority (host[:port]) for a target.

    The port is included only when it differs from the scheme's default
    (80 for http, 443 for https), so existing commands built against
    default-port targets stay byte-identical - historical evidence records
    reference exact command strings.
    """
    host = target["host"]
    port = target["port"]
    if port == DEFAULT_SCHEME_PORTS.get(scheme):
        return host
    return f"{host}:{port}"


def _http_flags(scheme: str, *extra: str) -> list[str]:
    return ["-s", *extra, "-k"] if scheme == "https" else ["-s", *extra]


def _nmap_command(target: dict) -> list[str]:
    # Full range, not just the registered port: this test is the evidence
    # source for the "unnecessary services" control, which requires finding
    # services BEYOND the ones already registered.
    return ["nmap", "-sV", "-p-", target["host"]]


def _parse_nmap_observations(target: dict, output: str) -> dict:
    ports = sorted({int(m) for m in re.findall(r"^(\d+)/tcp\s+open", output, re.MULTILINE)})
    return {"open_ports": ports, "telnet_open": 23 in ports}


def _login_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme)
    authority = _authority_for(target, scheme)
    return [
        "curl", *flags, "-X", "POST", f"{scheme}://{authority}/login",
        "-d", "username=admin&password=admin",
    ]


def _parse_login_observations(target: dict, output: str) -> dict:
    return {"default_creds": "Login successful" in output}


def _headers_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme, "-I")
    authority = _authority_for(target, scheme)
    return ["curl", *flags, f"{scheme}://{authority}/"]


def _parse_headers_observations(target: dict, output: str) -> dict:
    lowered = output.lower()
    missing = [h for h in ("X-Frame-Options", "Content-Security-Policy") if h.lower() not in lowered]
    return {"missing_security_headers": missing}


def _anon_access_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme)
    authority = _authority_for(target, scheme)
    return ["curl", *flags, f"{scheme}://{authority}/api/config"]


def _parse_anon_access_observations(target: dict, output: str) -> dict:
    return {
        "anonymous_access_allowed": '"cred_mode"' in output,
        "api_key_exposed": '"api_key"' in output,
    }


def _session_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme, "-i")
    authority = _authority_for(target, scheme)
    return [
        "curl", *flags, "-X", "POST", f"{scheme}://{authority}/login",
        "-d", "username=admin&password=admin",
        "--next", *flags, f"{scheme}://{authority}/dashboard",
    ]


def _parse_session_observations(target: dict, output: str) -> dict:
    # Split on each response's status line rather than requiring it to start
    # a text line: curl concatenates the two --next responses back to back,
    # and a JSON body has no guaranteed trailing newline before the next
    # status line starts.
    chunks = [c for c in re.split(r"(?=HTTP/\d(?:\.\d)? \d{3})", output) if c.strip()]
    login_chunk = chunks[0] if chunks else ""
    dashboard_chunk = chunks[1] if len(chunks) > 1 else ""
    return {
        "session_cookie_issued": "set-cookie" in login_chunk.lower(),
        "dashboard_accessible_without_session": bool(
            re.match(r"HTTP/\d(?:\.\d)? 200", dashboard_chunk)
        ),
    }


def _admin_unauth_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme, "-i")
    authority = _authority_for(target, scheme)
    return ["curl", *flags, f"{scheme}://{authority}/api/admin/reset"]


def _parse_admin_unauth_observations(target: dict, output: str) -> dict:
    match = re.search(r"^HTTP/\d(\.\d)?\s+(\d{3})", output, re.MULTILINE)
    status = int(match.group(2)) if match else None
    return {"admin_unauthenticated": status == 200}


def _http_inspect_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme, "-i")
    authority = _authority_for(target, scheme)
    return [
        "curl", *flags, "-w", "\nHTTP_VERSION:%{http_version}\n",
        f"{scheme}://{authority}/",
    ]


def _parse_http_inspect_observations(target: dict, output: str) -> dict:
    server = re.search(r"^Server:\s*(.+)$", output, re.MULTILINE | re.IGNORECASE)
    version = re.search(r"HTTP_VERSION:(\S+)", output)
    banner = server.group(1).strip() if server else None
    return {
        "server_banner": banner,
        "http_version": version.group(1) if version else None,
        "banner_discloses_framework": bool(banner and "uvicorn" in banner.lower()),
    }


def _mqtt_command(target: dict) -> list[str]:
    return [
        "mosquitto_sub", "-h", target["host"], "-p", str(target["port"]),
        "-t", "devices/#", "-C", "1", "-W", "15", "-v",
    ]


def _parse_mqtt_observations(target: dict, output: str) -> dict:
    lowered = output.lower()
    error_markers = ("error", "not authorised", "not authorized", "connection refused")
    connected = "devices/" in output and not any(m in lowered for m in error_markers)
    return {
        "mqtt_tls": target["service_type"] == "mqtts",
        "mqtt_anonymous": connected,
    }


def _tls_command(target: dict) -> list[str]:
    # Worker's stdin is already /dev/null (see job_runner's detached CMD), so
    # s_client gets an immediate EOF and exits after printing the handshake -
    # no explicit stdin redirect is needed or possible without a shell.
    return ["openssl", "s_client", "-connect", f"{target['host']}:{target['port']}", "-brief"]


def _parse_tls_observations(target: dict, output: str) -> dict:
    version = re.search(r"Protocol version:\s*(\S+)", output)
    return {
        "tls_version": version.group(1) if version else None,
        # OpenSSL's default security level (2) rejects RSA keys under 2048
        # bits with this exact verify error - the same signal that already
        # distinguishes the lab's weak 1024-bit cert from the strong one in
        # committed raw output (EV-2026-07-08-0019 vs -0020).
        "weak_cipher": "certificate key too weak" in output.lower(),
    }


def _packet_capture_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    return [
        "python3", "/work/lab/auditor/worker/scan_scripts/packet_capture.py",
        target["host"], str(target["port"]), scheme,
    ]


def _parse_packet_capture_observations(target: dict, output: str) -> dict:
    count = re.search(r"packets_captured=(\d+)", output)
    plaintext = re.search(r"plaintext_get_visible=(True|False)", output)
    return {
        "packets_captured": int(count.group(1)) if count else 0,
        # True is the bad/expected outcome for a plain-HTTP target; False is
        # the good/expected outcome for HTTPS - don't "fix" this to always
        # read as a failure signal.
        "plaintext_get_visible": plaintext.group(1) == "True" if plaintext else None,
    }


def _firmware_command(check_name: str):
    def build(target: dict) -> list[str]:
        return ["python3", FIRMWARE_CHECK_SCRIPT, target["device_id"], check_name]
    return build


def _parse_fw_version_observations(target: dict, output: str) -> dict:
    present = "version_file_present=True" in output
    version = re.search(r"^firmware_version=(.*)$", output, re.MULTILINE)
    return {
        "version_file_present": present,
        "firmware_version": version.group(1) if version and present else None,
    }


def _parse_fw_config_observations(target: dict, output: str) -> dict:
    present = "config_files_present=True" in output
    files = re.search(r"^config_files=(.*)$", output, re.MULTILINE)
    members = [m for m in (files.group(1) if files else "").split(",") if m]
    return {"config_files_present": present, "config_files": members}


def _parse_fw_secrets_observations(target: dict, output: str) -> dict:
    return {"hardcoded_secret_found": "hardcoded_secret_found=True" in output}


def _parse_fw_apikey_observations(target: dict, output: str) -> dict:
    return {"api_key_found": "api_key_found=True" in output}


def _parse_fw_certkey_observations(target: dict, output: str) -> dict:
    return {"cert_or_key_present": "cert_or_key_present=True" in output}


def _parse_fw_manifest_observations(target: dict, output: str) -> dict:
    present = "manifest_present=True" in output
    packages_line = re.search(r"^packages=(.*)$", output, re.MULTILINE)
    packages = []
    if present and packages_line and packages_line.group(1):
        for entry in packages_line.group(1).split(","):
            name, _, version = entry.partition(":")
            packages.append({"name": name, "version": version})
    return {"manifest_present": present, "packages": packages}


def _parse_fw_updatescript_observations(target: dict, output: str) -> dict:
    present = "update_script_present=True" in output
    first_line = re.search(r"^first_line=(.*)$", output, re.MULTILINE)
    return {
        "update_script_present": present,
        "update_script_first_line": first_line.group(1) if first_line and present else None,
    }


SCAN_CATALOG = {
    "TEST-NET-PORTSCAN": {
        "label": "Nmap service/port scan",
        "tool": "nmap",
        "tool_version_command": ["nmap", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": ALL_SERVICE_TYPES,
        "build_command": _nmap_command,
        "parse_observations": _parse_nmap_observations,
    },
    "TEST-AUTH-DEFAULT-CREDS": {
        "label": "Default credentials (admin/admin)",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _login_command,
        "parse_observations": _parse_login_observations,
    },
    "TEST-HTTP-HEADERS": {
        "label": "HTTP security headers",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _headers_command,
        "parse_observations": _parse_headers_observations,
    },
    "TEST-AUTH-ANON-ACCESS": {
        "label": "Anonymous access",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _anon_access_command,
        "parse_observations": _parse_anon_access_observations,
    },
    "TEST-AUTH-SESSION": {
        "label": "Weak session behavior",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _session_command,
        "parse_observations": _parse_session_observations,
    },
    "TEST-ADMIN-UNAUTH": {
        "label": "Unprotected administrative endpoint",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _admin_unauth_command,
        "parse_observations": _parse_admin_unauth_observations,
    },
    "TEST-NET-HTTP-INSPECT": {
        "label": "HTTP inspection",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _http_inspect_command,
        "parse_observations": _parse_http_inspect_observations,
    },
    "TEST-MQTT-OPEN": {
        "label": "MQTT anonymous access",
        "tool": "mosquitto_sub",
        "tool_version_command": ["mosquitto_sub", "--help"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": MQTT_SERVICE_TYPES,
        "build_command": _mqtt_command,
        "parse_observations": _parse_mqtt_observations,
    },
    "TEST-TLS-CONFIG": {
        "label": "TLS configuration",
        "tool": "openssl",
        "tool_version_command": ["openssl", "version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": TLS_SERVICE_TYPES,
        "build_command": _tls_command,
        "parse_observations": _parse_tls_observations,
    },
    "TEST-NET-PKTCAPTURE": {
        "label": "Packet capture",
        "tool": "tcpdump",
        "tool_version_command": ["tcpdump", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _packet_capture_command,
        "parse_observations": _parse_packet_capture_observations,
    },
    "TEST-FW-VERSION": {
        "label": "Version file",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("version"),
        "parse_observations": _parse_fw_version_observations,
    },
    "TEST-FW-CONFIG": {
        "label": "Configuration files",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("config"),
        "parse_observations": _parse_fw_config_observations,
    },
    "TEST-FW-SECRETS": {
        "label": "Hard-coded password or secrets",
        "tool": "yara",
        "tool_version_command": ["python3", "-c", "import yara; print(yara.__version__)"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("secrets"),
        "parse_observations": _parse_fw_secrets_observations,
    },
    "TEST-FW-APIKEY": {
        "label": "API keys",
        "tool": "yara",
        "tool_version_command": ["python3", "-c", "import yara; print(yara.__version__)"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("apikey"),
        "parse_observations": _parse_fw_apikey_observations,
    },
    "TEST-FW-CERTKEY": {
        "label": "Certificate or key file",
        "tool": "yara",
        "tool_version_command": ["python3", "-c", "import yara; print(yara.__version__)"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("certkey"),
        "parse_observations": _parse_fw_certkey_observations,
    },
    "TEST-FW-MANIFEST": {
        "label": "Packet manifest",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("manifest"),
        "parse_observations": _parse_fw_manifest_observations,
    },
    "TEST-FW-UPDATESCRIPT": {
        "label": "Update script",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("updatescript"),
        "parse_observations": _parse_fw_updatescript_observations,
    },
}


def is_applicable(target: dict, test_id: str) -> bool:
    spec = SCAN_CATALOG.get(test_id)
    if spec is None:
        return False
    return target.get("service_type") in spec["applicable_service_types"]


def is_firmware_test(test_id: str) -> bool:
    spec = SCAN_CATALOG.get(test_id)
    return spec is not None and spec["category"] == CATEGORY_FIRMWARE
