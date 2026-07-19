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
"""

HTTP_SERVICE_TYPES = ("http", "https")
ALL_SERVICE_TYPES = ("http", "https", "mqtt", "mqtts", "telnet", "ssh")


def _scheme_for(target: dict) -> str:
    return "https" if target["service_type"] == "https" else "http"


def _nmap_command(target: dict) -> list[str]:
    # Full range, not just the registered port: this test is the evidence
    # source for the "unnecessary services" control, which requires finding
    # services BEYOND the ones already registered.
    return ["nmap", "-sV", "-p-", target["host"]]


def _parse_nmap_observations(target: dict, output: str) -> dict:
    import re

    ports = sorted({int(m) for m in re.findall(r"^(\d+)/tcp\s+open", output, re.MULTILINE)})
    return {"open_ports": ports, "telnet_open": 23 in ports}


def _login_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = ["-s", "-k"] if scheme == "https" else ["-s"]
    return [
        "curl", *flags, "-X", "POST", f"{scheme}://{target['host']}/login",
        "-d", "username=admin&password=admin",
    ]


def _parse_login_observations(target: dict, output: str) -> dict:
    return {"default_creds": "Login successful" in output}


def _headers_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = ["-s", "-k", "-I"] if scheme == "https" else ["-s", "-I"]
    return ["curl", *flags, f"{scheme}://{target['host']}/"]


def _parse_headers_observations(target: dict, output: str) -> dict:
    lowered = output.lower()
    missing = [h for h in ("X-Frame-Options", "Content-Security-Policy") if h.lower() not in lowered]
    return {"missing_security_headers": missing}


SCAN_CATALOG = {
    "TEST-NET-PORTSCAN": {
        "label": "Nmap service/port scan",
        "tool": "nmap",
        "tool_version_command": ["nmap", "--version"],
        "applicable_service_types": ALL_SERVICE_TYPES,
        "build_command": _nmap_command,
        "parse_observations": _parse_nmap_observations,
    },
    "TEST-AUTH-DEFAULT-CREDS": {
        "label": "Default credentials (admin/admin)",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _login_command,
        "parse_observations": _parse_login_observations,
    },
    "TEST-HTTP-HEADERS": {
        "label": "HTTP security headers",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _headers_command,
        "parse_observations": _parse_headers_observations,
    },
}


def is_applicable(target: dict, test_id: str) -> bool:
    spec = SCAN_CATALOG.get(test_id)
    if spec is None:
        return False
    return target.get("service_type") in spec["applicable_service_types"]
