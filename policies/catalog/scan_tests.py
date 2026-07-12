"""Whitelisted scan tests for the dashboard's live "Run Scan" feature.

Security boundary: device_id and test_id are always validated against this
fixed catalog before anything runs. Commands are built as argv lists (never
a shell string), so even a bypassed validation has no shell-injection
surface. auditor-api never executes a command itself — it only ever
creates/reads scan_jobs rows; auditor-worker is the sole executor, and it
re-validates against this same catalog before running anything.

Finding text is deliberately NOT produced here. Observations are simple,
mechanical parses of real tool output (port numbers, string matches) - the
same category of fact a human would read off the screen, just automated.
The security *interpretation* (the "finding") is still typed by a human in
the dashboard before evidence is recorded, matching the CLI-driven flow
this mirrors (record_evidence.py).
"""

DEVICE_SCHEME = {
    "device-insecure": "http",
    "device-partial": "https",
    "device-hardened": "https",
}


def _nmap_command(device_id: str) -> list[str]:
    if device_id == "telnet-sim":
        return ["nmap", "-sV", "-p", "23", device_id]
    return ["nmap", "-sV", "-p-", device_id]


def _parse_nmap_observations(device_id: str, output: str) -> dict:
    import re

    ports = sorted({int(m) for m in re.findall(r"^(\d+)/tcp\s+open", output, re.MULTILINE)})
    return {"open_ports": ports, "telnet_open": 23 in ports}


def _login_command(device_id: str) -> list[str]:
    scheme = DEVICE_SCHEME[device_id]
    flags = ["-sk"] if scheme == "https" else ["-s"]
    return ["curl", *flags, "-X", "POST", f"{scheme}://{device_id}/login",
            "-d", "username=admin&password=admin"]


def _parse_login_observations(device_id: str, output: str) -> dict:
    return {"default_creds": "Login successful" in output}


def _headers_command(device_id: str) -> list[str]:
    scheme = DEVICE_SCHEME[device_id]
    flags = ["-sk"] if scheme == "https" else ["-s"]
    return ["curl", *flags, "-I", f"{scheme}://{device_id}/"]


def _parse_headers_observations(device_id: str, output: str) -> dict:
    lowered = output.lower()
    missing = [h for h in ("X-Frame-Options", "Content-Security-Policy") if h.lower() not in lowered]
    return {"missing_security_headers": missing}


SCAN_CATALOG = {
    "TEST-NET-PORTSCAN": {
        "label": "Nmap service/port scan",
        "tool": "nmap",
        "tool_version_command": ["nmap", "--version"],
        "allowed_devices": ["device-insecure", "device-partial", "device-hardened", "telnet-sim"],
        "build_command": _nmap_command,
        "parse_observations": _parse_nmap_observations,
    },
    "TEST-AUTH-DEFAULT-CREDS": {
        "label": "Default credentials (admin/admin)",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "allowed_devices": ["device-insecure", "device-partial", "device-hardened"],
        "build_command": _login_command,
        "parse_observations": _parse_login_observations,
    },
    "TEST-HTTP-HEADERS": {
        "label": "HTTP security headers",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "allowed_devices": ["device-insecure", "device-partial", "device-hardened"],
        "build_command": _headers_command,
        "parse_observations": _parse_headers_observations,
    },
}


def is_allowed(device_id: str, test_id: str) -> bool:
    spec = SCAN_CATALOG.get(test_id)
    return spec is not None and device_id in spec["allowed_devices"]
