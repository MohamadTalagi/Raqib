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

from policies.catalog.vuln_reference import lookup_component

HTTP_SERVICE_TYPES = ("http", "https")
MQTT_SERVICE_TYPES = ("mqtt", "mqtts")
TLS_SERVICE_TYPES = ("https", "mqtts")
ALL_SERVICE_TYPES = ("http", "https", "mqtt", "mqtts", "telnet", "ssh")

DEFAULT_SCHEME_PORTS = {"http": 80, "https": 443}

CATEGORY_WEB_AUTH = "web-and-auth"
CATEGORY_NETWORK_PROTOCOL = "network-and-protocol"
CATEGORY_FIRMWARE = "firmware"

FIRMWARE_CHECK_SCRIPT = "/work/lab/auditor/worker/scan_scripts/firmware_check.py"

# The 10 most commonly documented IoT default credential pairs (widely
# published, e.g. in the Mirai botnet's credential list and OWASP IoT
# guidance) - checked against whatever product is registered, not one
# specific device's known seed credentials, so this stays meaningful for
# any IoT product an auditor registers, not just this lab's smart camera.
DEFAULT_CREDENTIAL_PAIRS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "admin"),
    ("admin", ""),
    ("admin", "12345"),
    ("user", "user"),
    ("guest", "guest"),
]


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


REACHABILITY_CHECK_SCRIPT = "/work/lab/auditor/worker/scan_scripts/reachability_check.py"


def _reachability_command(target: dict) -> list[str]:
    return ["python3", REACHABILITY_CHECK_SCRIPT, target["host"], str(target["port"])]


def _parse_reachability_observations(target: dict, output: str) -> dict:
    reachable = "reachable=True" in output
    error = re.search(r"^error=(.+)$", output, re.MULTILINE)
    notes = (
        [f"Could not open a TCP connection to {target['host']}:{target['port']}."]
        if not reachable
        else [f"{target['host']}:{target['port']} accepted a TCP connection."]
    )
    return {
        "reachable": reachable,
        "error": error.group(1) if error else None,
        "notes": notes,
    }


def _nmap_command(target: dict) -> list[str]:
    # Full range, not just the registered port: this test is the evidence
    # source for the "unnecessary services" control, which requires finding
    # services BEYOND the ones already registered.
    return ["nmap", "-sV", "-p-", target["host"]]


def _parse_nmap_observations(target: dict, output: str) -> dict:
    ports = sorted({int(m) for m in re.findall(r"^(\d+)/tcp\s+open", output, re.MULTILINE)})
    telnet_open = 23 in ports
    # nmap -sV's SERVICE/VERSION columns, when present - service is the
    # protocol nmap identified (e.g. "http"), version is free-form product
    # text (e.g. "Werkzeug httpd 2.0.1") that doesn't line up with this
    # catalog's small (name, version) vuln reference keys reliably enough to
    # auto-lookup, so it's surfaced for the auditor to check by hand instead
    # of guessing at a match.
    services = []
    for match in re.finditer(r"^(\d+)/tcp[ \t]+open[ \t]+(\S+)(?:[ \t]+(.+?))?[ \t]*$", output, re.MULTILINE):
        services.append({
            "port": int(match.group(1)),
            "service": match.group(2),
            "version": match.group(3).strip() if match.group(3) else None,
        })
    notes = []
    if telnet_open:
        notes.append(
            "Telnet (port 23) is open - it transmits credentials and traffic "
            "in cleartext with no encryption option; remove it unless "
            "explicitly required.",
        )
    if any(s["version"] for s in services):
        notes.append(
            "One or more services disclosed version information - cross-check "
            "each against a live CVE database (this catalog's local reference "
            "only covers firmware packages, not arbitrary nmap version strings).",
        )
    return {
        "open_ports": ports,
        "services": services,
        "notes": notes,
    }


def _login_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    authority = _authority_for(target, scheme)
    login_url = f"{scheme}://{authority}/login"
    # One curl invocation, chained via --next - still a single argv list
    # (never a shell string), just one request per credential pair. -i is
    # needed (not just -s) so each response's status line is available as a
    # delimiter when splitting the concatenated output back into per-pair
    # chunks in _parse_login_observations.
    command: list[str] = ["curl"]
    for index, (username, password) in enumerate(DEFAULT_CREDENTIAL_PAIRS):
        if index > 0:
            command.append("--next")
        command += _http_flags(scheme, "-i", "-X", "POST")
        command += [login_url, "-d", f"username={username}&password={password}"]
    return command


def _parse_login_observations(target: dict, output: str) -> dict:
    chunks = [c for c in re.split(r"(?=HTTP/\d(?:\.\d)? \d{3})", output) if c.strip()]
    tried = [{"username": u, "password": p} for u, p in DEFAULT_CREDENTIAL_PAIRS]
    working = [
        pair
        for pair, chunk in zip(tried, chunks)
        if "Login successful" in chunk
    ]
    default_creds = bool(working)
    notes = (
        [
            "Accepted default credential pair(s): "
            + ", ".join(f"{c['username']}:{c['password'] or '(blank)'}" for c in working)
            + " - this gives any network-adjacent party full administrative "
            "control. Force a unique password on first boot, not just at "
            "manual setup time.",
        ]
        if default_creds
        else [f"None of the {len(tried)} tried default credential pairs were accepted."]
    )
    return {
        "default_creds": default_creds,
        "credentials_tried": tried,
        "working_credentials": working,
        "notes": notes,
    }


def _headers_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme, "-I")
    authority = _authority_for(target, scheme)
    return ["curl", *flags, f"{scheme}://{authority}/"]


HEADER_RISK_NOTES = {
    "X-Frame-Options": (
        "Missing X-Frame-Options - the page can be embedded in a hidden "
        "iframe on an attacker's site, enabling clickjacking against any "
        "admin UI served here."
    ),
    "Content-Security-Policy": (
        "Missing Content-Security-Policy - there is no browser-enforced "
        "restriction on which scripts/origins can run, widening the impact "
        "of any XSS found elsewhere on this service."
    ),
}


def _parse_headers_observations(target: dict, output: str) -> dict:
    lowered = output.lower()
    missing = [h for h in ("X-Frame-Options", "Content-Security-Policy") if h.lower() not in lowered]
    notes = [HEADER_RISK_NOTES[h] for h in missing] or ["Both checked security headers are present."]
    return {"missing_security_headers": missing, "notes": notes}


def _anon_access_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme)
    authority = _authority_for(target, scheme)
    return ["curl", *flags, f"{scheme}://{authority}/api/config"]


def _parse_anon_access_observations(target: dict, output: str) -> dict:
    anonymous_access_allowed = '"cred_mode"' in output
    api_key_exposed = '"api_key"' in output
    notes = []
    if anonymous_access_allowed:
        notes.append(
            "The config endpoint returned data with no credentials supplied "
            "- device configuration is readable by any network-adjacent party.",
        )
    if api_key_exposed:
        notes.append(
            "A live API key was present in the unauthenticated response - "
            "rotate it immediately if this device is anything other than a "
            "sandboxed lab fixture, since it is now effectively public.",
        )
    if not notes:
        notes.append("No anonymous access or API key exposure detected on this endpoint.")
    return {
        "anonymous_access_allowed": anonymous_access_allowed,
        "api_key_exposed": api_key_exposed,
        "notes": notes,
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
    session_cookie_issued = "set-cookie" in login_chunk.lower()
    dashboard_accessible_without_session = bool(re.match(r"HTTP/\d(?:\.\d)? 200", dashboard_chunk))
    notes = []
    if not session_cookie_issued:
        notes.append(
            "No session cookie was issued on login - if the dashboard is "
            "reachable without one (see below), there is effectively no "
            "session boundary protecting it at all.",
        )
    if dashboard_accessible_without_session:
        notes.append(
            "The dashboard was reachable using a fresh client with no "
            "session state carried over from login - authentication is not "
            "actually being enforced on this page.",
        )
    if not notes:
        notes.append("A session cookie was issued and the dashboard was not reachable without it.")
    return {
        "session_cookie_issued": session_cookie_issued,
        "dashboard_accessible_without_session": dashboard_accessible_without_session,
        "notes": notes,
    }


def _admin_unauth_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme, "-i")
    authority = _authority_for(target, scheme)
    return ["curl", *flags, f"{scheme}://{authority}/api/admin/reset"]


def _parse_admin_unauth_observations(target: dict, output: str) -> dict:
    match = re.search(r"^HTTP/\d(\.\d)?\s+(\d{3})", output, re.MULTILINE)
    status = int(match.group(2)) if match else None
    admin_unauthenticated = status == 200
    notes = (
        [
            "The administrative reset endpoint executed with no "
            "Authorization header - any network-adjacent party can trigger "
            "an administrative action with zero authentication.",
        ]
        if admin_unauthenticated
        else ["The administrative endpoint rejected the unauthenticated request."]
    )
    return {"admin_unauthenticated": admin_unauthenticated, "notes": notes}


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
    # Any non-empty Server header discloses something about the underlying
    # stack to reconnaissance - this isn't limited to one named framework so
    # it stays meaningful for whatever product is registered, not just this
    # lab's own smart-camera app.
    banner_discloses_framework = bool(banner)
    # Best-effort "name/version" or "name version" split (e.g. "nginx/1.18.0")
    # so a recognized component gets a real vuln_reference lookup instead of
    # only being flagged as "discloses a framework" with no follow-up data.
    component_advisory = None
    name_version = re.match(r"^([A-Za-z][\w.+-]*)[\s/]+([\d][\w.-]*)", banner or "")
    if name_version:
        component_advisory = lookup_component(name_version.group(1), name_version.group(2))
    notes = []
    if banner_discloses_framework:
        notes.append(
            "The Server header discloses the underlying framework - "
            "consider suppressing or genericizing it to reduce the "
            "information available to an attacker doing reconnaissance.",
        )
    if not notes:
        notes.append("Server header did not disclose recognizable framework information.")
    return {
        "server_banner": banner,
        "http_version": version.group(1) if version else None,
        "banner_discloses_framework": banner_discloses_framework,
        "component_advisory": component_advisory,
        "notes": notes,
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
    mqtt_tls = target["service_type"] == "mqtts"
    notes = []
    if connected:
        notes.append(
            "The broker accepted a subscription with no credentials - any "
            "client on the network can read (and, unless ACLs are set, "
            "publish to) every topic.",
        )
    if not mqtt_tls:
        notes.append(
            "MQTT traffic is unencrypted - payloads and any credentials "
            "used are visible to anyone who can observe the network path.",
        )
    if not notes:
        notes.append("Anonymous access was rejected and the connection is TLS-protected.")
    return {
        "mqtt_tls": mqtt_tls,
        "mqtt_anonymous": connected,
        "notes": notes,
    }


TLS_CERT_CHECK_SCRIPT = "/work/lab/auditor/worker/scan_scripts/tls_cert_check.py"


def _tls_command(target: dict) -> list[str]:
    # A single `openssl s_client -brief` can't also report the certificate's
    # notBefore/notAfter dates without a second `openssl x509` invocation fed
    # its PEM output on stdin - not expressible as one argv command without a
    # shell pipe, so this delegates to a small compound script that chains
    # both openssl calls and prints its output in the same shape the
    # original single invocation did (see tls_cert_check.py's own docstring).
    return ["python3", TLS_CERT_CHECK_SCRIPT, target["host"], str(target["port"])]


DEPRECATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _parse_tls_observations(target: dict, output: str) -> dict:
    version = re.search(r"Protocol version:\s*(\S+)", output)
    tls_version = version.group(1) if version else None
    # OpenSSL's default security level (2) rejects RSA keys under 2048
    # bits with this exact verify error - the same signal that already
    # distinguishes the lab's weak 1024-bit cert from the strong one in
    # committed raw output (EV-2026-07-08-0019 vs -0020).
    weak_cipher = "certificate key too weak" in output.lower()

    not_after = re.search(r"notAfter=(.+)$", output, re.MULTILINE)
    cert_expired = None
    if not_after:
        import datetime as _dt

        try:
            # openssl's notAfter= value is always UTC (it prints "GMT"), but
            # %Z doesn't reliably attach tzinfo for that abbreviation across
            # platforms - compare as naive UTC on both sides instead.
            expiry = _dt.datetime.strptime(not_after.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            now_utc = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
            cert_expired = expiry < now_utc
        except ValueError:
            cert_expired = None

    notes = []
    if weak_cipher:
        notes.append(
            "The certificate's key is below the 2048-bit minimum OpenSSL's "
            "default security level accepts - replace it with a 2048-bit-or-"
            "larger key.",
        )
    if tls_version in DEPRECATED_TLS_VERSIONS:
        notes.append(
            f"{tls_version} is deprecated and should be disabled in favor of "
            "TLS 1.2 or 1.3.",
        )
    if cert_expired:
        notes.append("The certificate has expired - reissue it before it is used to accept a real connection.")
    elif cert_expired is None:
        notes.append("Could not determine certificate expiry from the handshake output.")
    if not notes:
        notes.append("No weak key or deprecated protocol version detected.")
    return {
        "tls_version": tls_version,
        "weak_cipher": weak_cipher,
        "cert_expired": cert_expired,
        "notes": notes,
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
    # True is the bad/expected outcome for a plain-HTTP target; False is
    # the good/expected outcome for HTTPS - don't "fix" this to always
    # read as a failure signal.
    plaintext_get_visible = plaintext.group(1) == "True" if plaintext else None
    notes = (
        [
            "The request/response was visible in cleartext on the wire - "
            "any party with network visibility (a shared switch, a "
            "compromised router, a rogue AP) can read it in full.",
        ]
        if plaintext_get_visible
        else ["No plaintext application data was visible in the capture."]
    )
    return {
        "packets_captured": int(count.group(1)) if count else 0,
        "plaintext_get_visible": plaintext_get_visible,
        "notes": notes,
    }


def _firmware_command(check_name: str):
    def build(target: dict) -> list[str]:
        return ["python3", FIRMWARE_CHECK_SCRIPT, target["device_id"], check_name]
    return build


def _parse_fw_version_observations(target: dict, output: str) -> dict:
    present = "version_file_present=True" in output
    version = re.search(r"^firmware_version=(.*)$", output, re.MULTILINE)
    firmware_version = version.group(1) if version and present else None
    notes = (
        ["No VERSION file was found in the archive - firmware version cannot be tracked or correlated to a vendor advisory."]
        if not present
        else [
            "This local reference does not track CVEs against whole-device "
            "firmware version strings (see TEST-FW-MANIFEST for the "
            "individual package versions that make up this firmware, which "
            "are checked) - correlate this version against the vendor's own "
            "advisories.",
        ]
    )
    return {
        "version_file_present": present,
        "firmware_version": firmware_version,
        "notes": notes,
    }


def _parse_fw_config_observations(target: dict, output: str) -> dict:
    present = "config_files_present=True" in output
    files = re.search(r"^config_files=(.*)$", output, re.MULTILINE)
    members = [m for m in (files.group(1) if files else "").split(",") if m]
    notes = (
        [
            "Configuration file(s) shipped inside the firmware archive - "
            "review them for hard-coded hostnames, credentials, or other "
            "environment-specific values that shouldn't be baked into a "
            "shipped image.",
        ]
        if present
        else ["No configuration files were found in the archive."]
    )
    return {"config_files_present": present, "config_files": members, "notes": notes}


def _parse_fw_secrets_observations(target: dict, output: str) -> dict:
    found = "hardcoded_secret_found=True" in output
    notes = (
        [
            "A hard-coded password pattern was found in the archive - "
            "rotating the affected credential is not enough on its own, "
            "since every unit shipped with this firmware shares it.",
        ]
        if found
        else ["No hard-coded password pattern matched in the archive."]
    )
    return {"hardcoded_secret_found": found, "notes": notes}


def _parse_fw_apikey_observations(target: dict, output: str) -> dict:
    found = "api_key_found=True" in output
    notes = (
        [
            "An embedded API key pattern was found in the archive - treat "
            "it as compromised for every device running this firmware "
            "image, not just this one unit.",
        ]
        if found
        else ["No embedded API key pattern matched in the archive."]
    )
    return {"api_key_found": found, "notes": notes}


def _parse_fw_certkey_observations(target: dict, output: str) -> dict:
    present = "cert_or_key_present=True" in output
    notes = (
        [
            "A private key or certificate file was found inside the "
            "firmware archive - a key shared across every unit of this "
            "device model cannot uniquely authenticate a single device, "
            "and its compromise affects the whole fleet.",
        ]
        if present
        else ["No certificate or private key file was found in the archive."]
    )
    return {"cert_or_key_present": present, "notes": notes}


def _parse_fw_manifest_observations(target: dict, output: str) -> dict:
    present = "manifest_present=True" in output
    packages_line = re.search(r"^packages=(.*)$", output, re.MULTILINE)
    packages = []
    if present and packages_line and packages_line.group(1):
        for entry in packages_line.group(1).split(","):
            name, _, version = entry.partition(":")
            packages.append(lookup_component(name, version))
    outdated_count = sum(1 for p in packages if p["outdated"])
    cve_count = sum(len(p["cves"]) for p in packages)
    notes = []
    if not present:
        notes.append("No manifest.json was found in the archive - component versions cannot be checked.")
    elif not packages:
        notes.append("manifest.json was present but listed no packages.")
    else:
        notes.append(
            f"{outdated_count} of {len(packages)} listed package(s) are outdated, "
            f"with {cve_count} known CVE(s) recorded in this local reference.",
        )
    return {"manifest_present": present, "packages": packages, "notes": notes}


def _parse_fw_updatescript_observations(target: dict, output: str) -> dict:
    present = "update_script_present=True" in output
    first_line = re.search(r"^first_line=(.*)$", output, re.MULTILINE)
    first_line_value = first_line.group(1) if first_line and present else None
    notes = []
    if not present:
        notes.append("No update script was found in the archive.")
    else:
        notes.append(
            "An update script was found - confirm elsewhere (TEST-FW-CERTKEY, "
            "or a signature-verification step in the script itself) that the "
            "downloaded firmware image is signature-checked before being "
            "applied, not just fetched and installed.",
        )
    return {
        "update_script_present": present,
        "update_script_first_line": first_line_value,
        "notes": notes,
    }


SCAN_CATALOG = {
    "TEST-NET-REACHABILITY": {
        "label": "Host reachability",
        "tool": "python3 (socket)",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": ALL_SERVICE_TYPES,
        "build_command": _reachability_command,
        "parse_observations": _parse_reachability_observations,
    },
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
