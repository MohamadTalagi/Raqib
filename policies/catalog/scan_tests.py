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

TEST-NET-DISCOVERY's "network-discovery" category is deliberately NOT a 4th
Run Scan section: it never needed a device to run against in the first
place (it always swept the whole subnet), so gating it behind "select a
device" was actively wrong, not just an omission. It's still in this
catalog (job_runner.py's process_network_scan reads it directly by key) and
still reachable per-device via POST /scan-jobs if something calls that API
directly, but the only real UI entry point is the standalone "Discover
devices" panel on the Devices page (POST /network-scans), which needs no
device selection at all.

TEST-ADMIN-UNAUTH, TEST-MQTT-OPEN and TEST-TLS-CONFIG are not new tests:
they were run manually per lab/auditor/worker/tests/run_catalog.md and
already have real evidence (document-store/evidence/EV-2026-07-08-0017,
-0019, -0020) and, for the latter two, existing NCA control bindings
(policies/controls/SA-IOT-004.yaml, SA-IOT-005.yaml on
observations.mqtt_tls / observations.weak_cipher). Wiring them in here
automates that gap - keep their established test_id and observation field
names exactly, or verdict recomputation silently stops matching them.
"""

import ipaddress
import json
import re

from policies.catalog.pqc_crypto_reference import (
    TIP_CERT_SIGNATURE_FAIL,
    TIP_FIRMWARE_CRYPTO_FAIL,
    TIP_FIRMWARE_CRYPTO_UNKNOWN,
    TIP_TLS_KEY_EXCHANGE_FAIL,
    firmware_crypto_pqc_status,
)
from policies.catalog import firmware_version_compare
from policies.catalog.vuln_reference import lookup_component

HTTP_SERVICE_TYPES = ("http", "https")
MQTT_SERVICE_TYPES = ("mqtt", "mqtts")
TLS_SERVICE_TYPES = ("https", "mqtts")
MODBUS_SERVICE_TYPES = ("modbus",)
RTSP_SERVICE_TYPES = ("rtsp",)
UPNP_SERVICE_TYPES = ("upnp",)
MDNS_SERVICE_TYPES = ("mdns",)
ALL_SERVICE_TYPES = (
    "http", "https", "mqtt", "mqtts", "telnet", "ssh", "modbus", "rtsp", "upnp", "mdns",
)

DEFAULT_SCHEME_PORTS = {"http": 80, "https": 443}

CATEGORY_WEB_AUTH = "web-and-auth"
CATEGORY_NETWORK_PROTOCOL = "network-and-protocol"
CATEGORY_FIRMWARE = "firmware"
CATEGORY_NETWORK_DISCOVERY = "network-discovery"
# A third "no live host:port" class, distinct from the two above. Firmware
# tests need an uploaded archive; network-discovery tests sweep a subnet.
# A device-intel test needs neither - only that the device is registered and
# already has identity data - so it cannot reuse either category: the firmware
# branch of main.py's _create_scan_job hard-rejects a device with no firmware
# uploaded, which is exactly the case this class exists to serve, and the
# network-discovery branch routes into job_runner's two-stage nmap
# orchestrator. See is_device_intel_test() below.
CATEGORY_DEVICE_INTEL = "device-intel"

# Dashboard-overhaul pipeline phase tagging - a separate axis from `category`
# above (category drives is_firmware_test()/is_network_discovery_test() and
# stays untouched). Which phase a test belongs to for the new guided-pipeline
# UI: "what is this device" (fingerprinting) vs "is it compliant" (sa_iot_
# compliance) vs "does it have known CVEs" (vuln_intelligence, deliberately
# scoped to TEST-FW-MANIFEST only - the one test that actually produces CVE/
# CVSS/CISA-KEV data, not every firmware check). TEST-NET-DISCOVERY gets no
# phase tag - it's the standalone subnet sweep, already its own thing.
PIPELINE_PHASE_FINGERPRINTING = "fingerprinting"
PIPELINE_PHASE_SA_IOT_COMPLIANCE = "sa_iot_compliance"
PIPELINE_PHASE_VULN_INTELLIGENCE = "vuln_intelligence"
# Post-Quantum Readiness: a bonus stage beyond IoTGuard's original 10-stage
# vision, sitting after AI Remediation and before the AI Executive Summary.
# Purely informational - never feeds policies/risk/risk_engine.py, never a
# fourth SA-IOT/NCA-style compliance framework requiring sign-off.
PIPELINE_PHASE_PQC_READINESS = "pqc_readiness"

# The configurable set of subnets Network Discovery sweeps - mirrors
# device_validation.ALLOWED_NETWORKS (the boundary a registered device's
# host must fall inside), but kept as its own list of plain strings rather
# than imported, since scan_tests.py is shared code loaded by both
# auditor-api and auditor-worker and must not take on a dependency on
# device_validation.py's container-specific import path. Defaults to
# audit-network alone so an unconfigured process behaves exactly as this
# sweep always has; real configuration lives in the `network_scopes` table
# and is pushed in via configure_active_scopes() the same way
# device_validation.configure_allowed_networks() is - see that module's
# docstring for the full API-push / worker-poll split.
ACTIVE_SCOPES: list[str] = ["172.30.0.0/24"]


def configure_active_scopes(cidrs: list[str]) -> None:
    """Replaces the set of subnets Network Discovery sweeps. Called by
    auditor-api at startup and after every network_scopes write, and by
    auditor-worker's periodic refresh poll."""
    global ACTIVE_SCOPES
    ACTIVE_SCOPES = list(cidrs)

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


def _modbus_probe_command(target: dict) -> list[str]:
    # No -sV: confirmed live that nmap's generic service-version probes hang
    # against this fixture's minimal pymodbus TCP server, which (like many
    # real Modbus devices) never responds to a malformed/non-Modbus probe at
    # all rather than rejecting it - nmap then waits out its full per-probe
    # timeout. The modbus-discover script alone already identifies the
    # service and is real Modbus traffic our server does answer.
    # --script-timeout bounds the script itself: it can genuinely hang on a
    # server that doesn't answer whatever slave-id/function-code it tries,
    # which is itself an honest, real finding (see
    # _parse_modbus_probe_observations's "port open but no script data"
    # branch), not something to retry indefinitely for.
    return [
        "nmap", "--script-timeout", "10s", "--script", "modbus-discover",
        "-p", str(target["port"]), target["host"],
    ]


def _parse_modbus_probe_observations(target: dict, output: str) -> dict:
    port_open = re.search(rf"{target['port']}/tcp\s+open", output) is not None
    script_match = re.search(r"modbus-discover:\s*\n((?:\|.*\n?)*)", output)
    script_output = script_match.group(1).strip() if script_match else None
    if port_open and script_output:
        notes = [
            "Modbus TCP answered an unauthenticated discovery probe - the protocol "
            "has no native authentication or encryption, so any network-adjacent "
            "client can read or write this device's registers and coils.",
        ]
    elif port_open:
        notes = [
            "Modbus TCP port is open but the discovery script returned no data - "
            "manually verify read/write access with a Modbus client.",
        ]
    else:
        notes = [f"Modbus TCP port {target['port']} did not respond as open."]
    return {"modbus_port_open": port_open, "script_output": script_output, "notes": notes}


def _rtsp_probe_command(target: dict) -> list[str]:
    # No -sV, same reason as _modbus_probe_command: confirmed live it hangs
    # against this fixture's minimal RTSP responder, which keeps a
    # connection open rather than closing it the way nmap's generic probes
    # expect. rtsp-methods alone (real RTSP OPTIONS traffic) already
    # identifies the service and completes in well under a second.
    return [
        "nmap", "--script-timeout", "10s", "--script", "rtsp-methods",
        "-p", str(target["port"]), target["host"],
    ]


def _parse_rtsp_probe_observations(target: dict, output: str) -> dict:
    port_open = re.search(rf"{target['port']}/tcp\s+open", output) is not None
    # nmap actually prints this on one line (confirmed live):
    # "|_rtsp-methods: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN" -
    # not the 2-line "label, then |_ continuation" shape modbus-discover
    # uses. \n? tolerates either shape rather than assuming one.
    methods_match = re.search(r"rtsp-methods:\s*\n?\|?_?\s*(.+)", output)
    methods = [m.strip() for m in methods_match.group(1).split(",")] if methods_match else []
    unauthenticated_stream_access = "DESCRIBE" in methods or "PLAY" in methods
    if unauthenticated_stream_access:
        notes = [
            "RTSP responded to DESCRIBE/PLAY with no authentication challenge - "
            "the video stream can be viewed by any network-adjacent client.",
        ]
    elif port_open:
        notes = ["RTSP port is open but did not advertise DESCRIBE/PLAY - re-check manually."]
    else:
        notes = [f"RTSP port {target['port']} did not respond as open."]
    return {
        "rtsp_port_open": port_open,
        "methods": methods,
        "unauthenticated_stream_access": unauthenticated_stream_access,
        "notes": notes,
    }


UPNP_PROBE_SCRIPT = "/work/lab/auditor/worker/scan_scripts/upnp_probe.py"


def _upnp_probe_command(target: dict) -> list[str]:
    return ["python3", UPNP_PROBE_SCRIPT, target["host"], str(target["port"])]


def _parse_upnp_probe_observations(target: dict, output: str) -> dict:
    reachable = "reachable=True" in output
    response_match = re.search(r"response_start\n(.*?)\nresponse_end", output, re.DOTALL)
    response = response_match.group(1) if response_match else None
    server_match = re.search(r"^SERVER:\s*(.+)$", response or "", re.IGNORECASE | re.MULTILINE)
    server = server_match.group(1).strip() if server_match else None
    if reachable:
        detail = f" (SERVER: {server})" if server else ""
        notes = [
            f"Device answered an unauthenticated SSDP M-SEARCH query{detail} - "
            "UPnP discovery requires no credentials by protocol design, and this "
            "device's port-mapping API accepts requests the same way.",
        ]
    else:
        notes = ["No SSDP response received."]
    return {"upnp_reachable": reachable, "server_banner": server, "notes": notes}


MDNS_PROBE_SCRIPT = "/work/lab/auditor/worker/scan_scripts/mdns_probe.py"


def _mdns_probe_command(target: dict) -> list[str]:
    return ["python3", MDNS_PROBE_SCRIPT, target["host"], str(target["port"])]


def _decode_mdns_txt_record(packet: bytes) -> dict | None:
    """Decodes the TXT record produced by device-speaker's own responder
    (lab/devices/smart-speaker/app/mdns_server.py) - a private wire-format
    contract between that fixture and this probe, not a general-purpose
    mDNS/DNS-SD parser. Returns None rather than raising on anything
    malformed or truncated, since a real device might not use this exact
    shape."""
    try:
        offset = 12
        labels = []
        while packet[offset] != 0:
            length = packet[offset]
            offset += 1
            labels.append(packet[offset : offset + length].decode())
            offset += length
        offset += 1
        name = ".".join(labels)
        offset += 8
        offset += 2  # RDLENGTH
        txt_length = packet[offset]
        txt = packet[offset + 1 : offset + 1 + txt_length].decode()
        return {"name": name, "txt": dict(pair.split("=", 1) for pair in txt.split(";"))}
    except (IndexError, UnicodeDecodeError, ValueError):
        return None


def _parse_mdns_probe_observations(target: dict, output: str) -> dict:
    reachable = "reachable=True" in output
    hex_match = re.search(r"response_hex=([0-9a-f]+)", output)
    record = _decode_mdns_txt_record(bytes.fromhex(hex_match.group(1))) if hex_match else None
    if record:
        notes = [
            f"Device answered an unauthenticated mDNS query, disclosing "
            f"{record['txt']} in plaintext - mDNS has no access control by design.",
        ]
    elif reachable:
        notes = ["mDNS responder answered but the record could not be decoded."]
    else:
        notes = ["No mDNS response received."]
    return {"mdns_reachable": reachable, "txt_record": record, "notes": notes}


# Signature ports used to classify a discovered host without a live target
# (this test scans the whole audit-network subnet, not one registered
# device - see _network_discovery_command). Split into two tiers rather than
# one flat "IoT" list because the two tiers carry very different confidence:
# a management UI or an IoT messaging protocol is a strong, purpose-built
# signature in this lab's threat model, while Telnet/SSH alone are generic
# remote-administration protocols that plenty of non-IoT network gear (a
# switch, a legacy print server, a jump host) also expose - conflating the
# two would overclaim confidence the port alone doesn't support.
#
# 502 (Modbus) and 554 (RTSP) are added here since both are TCP and this
# sweep's nmap invocation is TCP-only (-sV with no -sU). 1900 (SSDP/UPnP) and
# 5353 (mDNS) are deliberately NOT added here - both are UDP-only services,
# so a TCP-only port-list sweep can never see them "open" no matter what's
# in this list. That gap is closed a different way, not by adding them here:
# _network_discovery_command also runs nmap's broadcast-upnp-info and
# broadcast-dns-service-discovery NSE scripts once per sweep, and
# _fold_broadcast_discovery_into_hosts() gives any device that answers one
# of those queries a real iot_device entry even with zero TCP ports open -
# this catalog's own device-router-gw fixture is live-verified reachable
# this way. (Both of this project's UDP-only fixtures, device-router-gw and
# device-speaker, also happen to expose an HTTP admin UI on port 80, so
# they'd still classify as iot_device via that TCP signature alone even
# without this fold-in - but a genuinely UDP-only device, with no TCP port
# open at all, is exactly the case this closes.)
IOT_SIGNATURE_PORTS = frozenset({80, 443, 1883, 8883, 502, 554})
AMBIGUOUS_PORTS = frozenset({22, 23})
NETWORK_DISCOVERY_PORTS = sorted(IOT_SIGNATURE_PORTS | AMBIGUOUS_PORTS)


def _network_discovery_command(target: dict) -> list[str]:
    # target is unused: this test sweeps the whole subnet rather than one
    # device's host/port, exactly like the firmware tests ignore host/port
    # and key on device_id alone. Restricted to a fixed, small port list
    # (rather than -p- across a /24) so the scan finishes reliably and every
    # open port found is one this catalog's classifier actually knows how to
    # interpret.
    #
    # Tuned deliberately gentle, not for speed: this is an IoT environment,
    # and many real IoT devices have weak network stacks that can become
    # slow or unresponsive under aggressive scanning. -T3 (Normal) rather
    # than -T4 (Aggressive, which nmap's own docs say assumes "a reasonably
    # fast and reliable network" - not a safe assumption for constrained IoT
    # gear); --max-rate caps the packet rate so no single burst can flood a
    # fragile target; --version-intensity 2 sends lighter service-
    # fingerprinting probes (default is 7) since the classifier only needs
    # the port number, not a deep version fingerprint. Verified live against
    # the real lab that this costs no real time here (~25s either way, since
    # the dominant factor for a /24 sweep is the mostly-silent discovery
    # phase, not per-host probe aggressiveness) - see docs/errors/029 for
    # why --open was also dropped (it was silently omitting live hosts with
    # none of these ports open, e.g. the subnet gateway, making "unknown" an
    # unreachable classification in practice).
    # nmap natively accepts multiple target specs in one invocation, so every
    # configured scope is swept in a single command rather than one per scope.
    #
    # --script broadcast-upnp-info,broadcast-dns-service-discovery folds SSDP
    # (UPnP) and mDNS discovery into this same sweep, closing the previous
    # TCP-only blind spot for a device that speaks only a UDP discovery
    # protocol with no TCP signature port open at all. Both scripts are
    # nmap's own `broadcast safe` category (live-confirmed on this project's
    # exact nmap 7.95) - a single query per script, once per scan, not
    # per-host, so this adds a small roughly-constant ~5-10s overhead
    # regardless of subnet size, not a per-host cost.
    ports = ",".join(str(p) for p in NETWORK_DISCOVERY_PORTS)
    return [
        "nmap", "-sV", "--version-intensity", "2", "-p", ports,
        "-T3", "--max-retries", "1", "--max-rate", "50",
        "--script", "broadcast-upnp-info,broadcast-dns-service-discovery",
        *ACTIVE_SCOPES,
    ]


# --- Two-phase discovery (subnet-size scalability) -------------------------
#
# A single `-sV` command sweeping an entire configured scope (the function
# above) does not scale past the /24 this project has always run at - the
# platform's own "adjustable subnets" feature (network_scope_routes.py,
# device_validation.MIN_SCOPE_PREFIX_LENGTH = 16) allows configuring a /16
# (65,534 usable addresses) today, and a flat full-service-detection sweep
# across that many addresses in one command cannot finish in any reasonable
# timeout. job_runner.py's `_run_network_discovery()` instead runs two
# separate nmap invocations: a fast whole-scope ping/ARP sweep (Stage A,
# this section) to find which addresses are even alive, then a full `-sV`
# scan (Stage B, below) targeted only at the addresses Stage A found -
# dramatically cheaper than probing dead addresses with a full service
# fingerprint. The single-command function above is kept as-is (unit-tested,
# still reachable directly via SCAN_CATALOG for anything that calls it that
# way) - job_runner.py's TEST-NET-DISCOVERY dispatch special-cases around it
# to the two-stage flow instead, the same way it already special-cases
# firmware tests around the generic build_command/parse_observations path.
# Revised upward from an initial 0.05s/address estimate after a real
# large-scope live-verification attempt (see estimate_stage_a_timeout's own
# docstring) showed a genuinely unrouted proxy scope taking dramatically
# longer than that packet-rate-only model predicted - a real finding, not a
# guess this project then chose to ignore.
STAGE_A_BASE_SECONDS = 15
STAGE_A_PER_ADDRESS_SECONDS = 0.3
STAGE_A_MAX_SECONDS = 7200
STAGE_B_BASE_SECONDS = 20
STAGE_B_PER_HOST_SECONDS = 3
STAGE_B_MAX_SECONDS = 1800


def total_usable_addresses(scopes: list[str]) -> int:
    """Sum of usable host addresses (network/broadcast excluded, floored at
    1 per scope so a /31 or /32 scope - unusual but not rejected by
    MIN_SCOPE_PREFIX_LENGTH alone - never contributes 0 or a negative
    count) across every configured scope."""
    total = 0
    for scope in scopes:
        network = ipaddress.ip_network(scope, strict=False)
        total += max(network.num_addresses - 2, 1)
    return total


def estimate_stage_a_timeout(scopes: list[str]) -> int:
    """Estimate only, deliberately generous - and revised upward once
    already from a real live-verification finding, not just a paper
    calculation. A real /24 on this project's own audit-network took 10.96s
    for 256 addresses at --max-rate 50 (fast, ARP-resolved, every address
    genuinely reachable on the L2 segment). A real attempt at a larger-scope
    proxy told a different story: adding a second, genuinely unrouted RFC1918
    scope (nothing in this lab's Docker topology actually routes to it) and
    sweeping both together did not finish within 554+ seconds for ~4,348
    total addresses before being killed - far past what a naive
    packets-per-second model predicts, and well past this function's own
    first-draft estimate for that same scope (227s, which the real job
    genuinely timed out against live). A smaller isolated check of the same
    kind of unrouted range (a /27, 32 addresses) came back in 6.12s but with
    every single address falsely reported "up" (no MAC address on any of
    them - not a real ARP-confirmed host), pointing at some kind of
    NAT/routing-reflection artifact in this specific Docker Desktop test
    environment for genuinely unroutable destinations, not a real host
    responding. Neither finding was fully root-caused within this task's
    scope (see docs/known-limitations.md) - the honest, safe response is a
    substantially larger per-address constant and a much higher cap, not a
    confident recalculation from an unresolved anomaly. Capped at
    STAGE_A_MAX_SECONDS so a misconfigured scope (or several summed
    together) still can't produce a truly unbounded timeout."""
    estimate = STAGE_A_BASE_SECONDS + STAGE_A_PER_ADDRESS_SECONDS * total_usable_addresses(scopes)
    return min(int(estimate), STAGE_A_MAX_SECONDS)


def estimate_stage_b_timeout(live_host_count: int) -> int:
    """Estimate only - derived from this project's one real full-sweep
    measurement (~57-62s for 14 live hosts with the Task 3 broadcast
    scripts included, most of that being fixed nmap/NSE startup cost, not
    per-host cost), padded generously beyond that single data point since
    live host *count* at true subnet-scale (hundreds of hosts on a real
    large VLAN) has never been measured by this project. Capped at
    STAGE_B_MAX_SECONDS."""
    estimate = STAGE_B_BASE_SECONDS + STAGE_B_PER_HOST_SECONDS * live_host_count
    return min(int(estimate), STAGE_B_MAX_SECONDS)


def _network_discovery_stage_a_command() -> list[str]:
    # -sn: ping/ARP host-discovery only, no port scan - dramatically cheaper
    # per-address than the full -sV scan Stage B does. For the
    # audit-network's directly-attached L2 segment this is nmap's own
    # ARP-based discovery (already proven live elsewhere in this catalog);
    # for a routed/non-local configured scope nmap automatically falls back
    # to ICMP/TCP ping probes. -n (no reverse DNS) is a deliberate departure
    # from a naive "just add -sn" approach: DNS resolution is a real,
    # separate, sometimes-slow phase of nmap's own workflow that Stage A has
    # no use for at all (Stage B's own parser already resolves/reports
    # hostnames for whichever addresses turn out to be live) - cutting it
    # keeps Stage A's only job, finding live addresses fast, as fast as
    # possible. --max-rate 50 kept even here, matching this project's
    # non-negotiable gentle-scanning posture - Stage A's speed comes from
    # skipping per-host service probing, not from raising the packet rate.
    return ["nmap", "-sn", "-n", "--max-retries", "1", "--max-rate", "50", *ACTIVE_SCOPES]


def _parse_stage_a_live_hosts(output: str) -> list[str]:
    """Extracts every live host's IP from a `-sn -n` ping-sweep's output.
    With -n (no reverse DNS), nmap's per-host header is always a bare IP,
    never "hostname (ip)" - live-confirmed against a real /24 sweep - so
    this is a simpler shape than Stage B's own block header, which still
    has to handle a resolved hostname. A dead address never gets a report
    line at all in nmap's default (non-verbose) output, so no "is it up"
    check is needed here - every IP this regex finds is live by definition."""
    return re.findall(r"^Nmap scan report for ([\d.]+)\s*$", output, re.MULTILINE)


def _network_discovery_stage_b_command(live_hosts: list[str]) -> list[str]:
    # Identical shape to _network_discovery_command above (same ports, same
    # gentle tuning, same broadcast scripts) but targeting Stage A's
    # explicit live-host IP list instead of a whole CIDR scope - the one
    # thing that actually makes two-phase discovery cheaper: a full -sV
    # probe only ever runs against addresses already confirmed alive,
    # never against the (usually large majority of a big scope) dead ones.
    if not live_hosts:
        return []
    ports = ",".join(str(p) for p in NETWORK_DISCOVERY_PORTS)
    return [
        "nmap", "-sV", "--version-intensity", "2", "-p", ports,
        "-T3", "--max-retries", "1", "--max-rate", "50",
        "--script", "broadcast-upnp-info,broadcast-dns-service-discovery",
        *live_hosts,
    ]


def _classify_host(open_ports: set[int]) -> tuple[str, str, str]:
    """Returns (classification, confidence, rationale). Never asserts a
    confident classification the port signature alone doesn't support -
    "uncertain"/"unknown" are real, intended outcomes, not a fallback bug."""
    iot_hits = sorted(open_ports & IOT_SIGNATURE_PORTS)
    if iot_hits:
        return (
            "iot_device",
            "high",
            "Exposed port(s) " + ", ".join(str(p) for p in iot_hits) + " - a management UI or IoT "
            "messaging-protocol port, treated as a strong IoT-appliance signature.",
        )
    ambiguous_hits = sorted(open_ports & AMBIGUOUS_PORTS)
    if ambiguous_hits:
        # Telnet (23) and SSH (22) are not equally strong signals even though
        # both land in this same "uncertain" classification bucket: Telnet is
        # a much stronger legacy-IoT/appliance indicator (real IoT/appliance
        # gear still ships it; ordinary modern Linux/network hosts almost
        # never enable it), while SSH alone is ubiquitous on non-IoT gear too
        # (any Linux box, a switch, a jump host) and carries little IoT
        # signal on its own. Conflating the two into one confidence value was
        # a real precision loss - a Telnet-open host (with or without SSH
        # also open) is upgraded to "medium"; an SSH-only host (no Telnet)
        # stays "low".
        if 23 in ambiguous_hits:
            return (
                "uncertain",
                "medium",
                "Telnet (23) was open" + (" alongside SSH (22)" if 22 in ambiguous_hits else "")
                + " - Telnet is a much stronger legacy-IoT/appliance signal than SSH, since ordinary "
                "modern Linux/network hosts rarely enable it, but no IoT-specific management UI or "
                "messaging-protocol port was seen, so this is not confidently classified as iot_device.",
            )
        return (
            "uncertain",
            "low",
            "Only SSH (22) was open, with no Telnet - SSH alone is ubiquitous on many non-IoT network "
            "appliances (a switch, a legacy server, any ordinary Linux host) too, so it is not being "
            "weighted as an IoT signal and this host cannot be confidently classified as an IoT device "
            "from this signature alone.",
        )
    return (
        "unknown",
        "low",
        "None of the scanned signature ports were open on this host - it is live, but its role could "
        "not be inferred from this scan.",
    )


def _prescan_broadcast_script_section(output: str, script_name: str, next_script_name: str | None = None) -> str:
    """Isolates one NSE broadcast script's own output from nmap's "Pre-scan
    script results:" block, which always precedes the first per-host
    "Nmap scan report for" block. Bounded by `next_script_name` (this
    catalog always invokes broadcast-upnp-info then
    broadcast-dns-service-discovery in that fixed order, so a simple
    substring bound is reliable here - no need for a general NSE-output
    parser) so one script's output is never misread as part of the other's.
    Returns "" (never raises) when the script produced no output at all -
    a real, honest outcome (no device on this scope answered that broadcast
    query), not a parse failure."""
    marker = f"{script_name}:"
    if marker not in output:
        return ""
    section = output.split(marker, 1)[1]
    if next_script_name:
        stop_marker = f"{next_script_name}:"
        if stop_marker in section:
            section = section.split(stop_marker, 1)[0]
    return section.split("\nNmap scan report for", 1)[0]


def _parse_broadcast_upnp_hosts(output: str) -> list[str]:
    """Parses nmap's broadcast-upnp-info NSE script output for every
    responding device's real IP - live-captured shape against this
    project's own device-router-gw fixture, confirmed with a real
    end-to-end UPnP discovery (M-SEARCH -> LOCATION -> description.xml
    fetch), for example:

        | broadcast-upnp-info:
        |   239.255.255.250
        |       Server: Linux/1.0 UPnP/1.0 Netgear/R7000
        |       Location: http://172.30.0.13:80/description.xml
        ...

    The device's real IP comes from its own "Location: http://<ip>:<port>/
    ..." line, not the block's own outer group label - live-confirmed that
    this script mislabels every entry with the multicast group address
    (239.255.255.250) instead of the real per-device address, so parsing
    the outer indentation would silently attribute every response to a
    fake IP."""
    section = _prescan_broadcast_script_section(output, "broadcast-upnp-info", "broadcast-dns-service-discovery")
    return re.findall(r"Location:\s*http://([\d.]+):\d+", section)


def _parse_broadcast_mdns_hosts(output: str) -> list[str]:
    """Parses nmap's broadcast-dns-service-discovery NSE script output for
    every responding device's IP: each host is grouped under its own
    top-level IP line (one indentation level less than the
    service-type/instance lines nested beneath it), per nmap's own
    documented output shape:

        | broadcast-dns-service-discovery:
        |   1.2.3.1
        |     _ssh._tcp.local
        |     _http._tcp.local
        ...

    Built from nmap's own documentation, not a positive live capture in
    this lab (see docs/known-limitations.md): this project's own
    device-speaker fixture is a minimal, hand-rolled mDNS responder that
    never implements the DNS-SD "_services._dns-sd._udp.local" PTR-
    enumeration convention this script specifically queries for, so it
    (correctly, honestly) produces no output against it here - a real
    DNS-SD-compliant device would. Live-confirmed this script runs cleanly
    and safely returns nothing rather than erroring when no device answers,
    exactly like every other broadcast/probe collector in this catalog
    degrades honestly when a signal is absent."""
    section = _prescan_broadcast_script_section(output, "broadcast-dns-service-discovery")
    return re.findall(r"^\|   ([\d.]+)\s*$", section, re.MULTILINE)


def _fold_broadcast_discovery_into_hosts(hosts: list[dict], upnp_ips: list[str], mdns_ips: list[str]) -> None:
    """Folds SSDP/mDNS broadcast-discovery signals into `hosts` in place:
    an IP that already has a host entry (from the TCP port-scan block) gets
    the signal appended to its discovery_signals list; a genuinely new IP
    (a UDP-only device with no TCP signature port open at all - the real
    scenario this closes a gap for) gets a brand-new high-confidence
    iot_device entry. Every existing host also gets "port_scan" recorded so
    discovery_signals is a complete picture, not just the newly-added
    broadcast ones."""
    for host in hosts:
        host["discovery_signals"] = ["port_scan"]
    by_ip = {host["ip"]: host for host in hosts}

    for ip, signal, protocol_label in (
        *((ip, "upnp_broadcast", "UPnP/SSDP") for ip in upnp_ips),
        *((ip, "mdns_broadcast", "mDNS") for ip in mdns_ips),
    ):
        existing = by_ip.get(ip)
        if existing:
            if signal not in existing["discovery_signals"]:
                existing["discovery_signals"].append(signal)
            continue
        new_host = {
            "ip": ip,
            "hostname": None,
            "open_ports": [],
            "services": [],
            "classification": "iot_device",
            "confidence": "high",
            "rationale": f"Responded to a {protocol_label} broadcast discovery query - a signal "
            "restricted to devices that speak an IoT/consumer discovery protocol - despite having no "
            "TCP signature port open in this sweep's port list.",
            "mac_address": None,
            "mac_vendor": None,
            "mac_vendor_source": None,
            "discovery_signals": [signal],
        }
        hosts.append(new_host)
        by_ip[ip] = new_host


def _parse_network_discovery_observations(target: dict, output: str) -> dict:
    # nmap's own per-host report header is the natural split point; the
    # first chunk (nmap's startup banner) is discarded since it precedes any
    # host block.
    blocks = re.split(r"\nNmap scan report for ", output)[1:]
    hosts = []
    for block in blocks:
        header_line, _, rest = block.partition("\n")
        header_match = re.match(r"^(.*?)\s+\(([\d.]+)\)\s*$", header_line.strip())
        if header_match:
            hostname, ip = header_match.group(1), header_match.group(2)
        else:
            hostname, ip = None, header_line.strip()

        open_ports: set[int] = set()
        services = []
        # [ \t]+, not \s+: \s also matches the newline itself, so a port line
        # with no version text (e.g. "23/tcp open  telnet?" alone) would
        # otherwise let the optional version group's leading \s+ absorb the
        # line break and swallow the NEXT port's entire line as this port's
        # "version" - the exact bug _parse_nmap_observations already avoids
        # the same way, confirmed live against a real multi-port nmap run.
        for port_match in re.finditer(r"^(\d+)/tcp[ \t]+open[ \t]+(\S+)(?:[ \t]+(.+?))?[ \t]*$", rest, re.MULTILINE):
            port = int(port_match.group(1))
            open_ports.add(port)
            services.append({
                "port": port,
                "service": port_match.group(2),
                "version": port_match.group(3).strip() if port_match.group(3) else None,
            })

        # nmap only prints a "MAC Address:" line when it resolved the host
        # via its own ARP-based host discovery on a directly-attached
        # Ethernet segment - this signal was already being generated by
        # every real sweep this project has ever run (confirmed by real
        # committed evidence, EV-2026-07-23-0001.txt) but silently discarded
        # here until now. The parenthetical is nmap's own bundled
        # (smaller, staler) OUI vendor guess - "Unknown" is nmap's own
        # honest "no match in my bundled table" answer, not a real vendor
        # name, so it's normalized to None here rather than surfaced as if
        # it were meaningful. job_runner.py enriches this further with a
        # maintained IEEE OUI-registry lookup (oui_lookup.py) after this
        # pure parser returns - a live network/filesystem lookup, so it
        # cannot happen in this module (see this file's own "stays pure"
        # rule) - overriding mac_vendor/mac_vendor_source when the registry
        # has a fresher answer than nmap's own bundled guess.
        mac_match = re.search(r"^MAC Address: ([0-9A-Fa-f:]+) \((.+)\)$", rest, re.MULTILINE)
        mac_address = mac_match.group(1) if mac_match else None
        nmap_vendor_guess = None
        if mac_match and mac_match.group(2) != "Unknown":
            nmap_vendor_guess = mac_match.group(2)

        classification, confidence, rationale = _classify_host(open_ports)
        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "open_ports": sorted(open_ports),
            "services": services,
            "classification": classification,
            "confidence": confidence,
            "rationale": rationale,
            "mac_address": mac_address,
            "mac_vendor": nmap_vendor_guess,
            "mac_vendor_source": "nmap_bundled" if nmap_vendor_guess else None,
        })

    upnp_ips = _parse_broadcast_upnp_hosts(output)
    mdns_ips = _parse_broadcast_mdns_hosts(output)
    _fold_broadcast_discovery_into_hosts(hosts, upnp_ips, mdns_ips)

    iot_count = sum(1 for h in hosts if h["classification"] == "iot_device")
    uncertain_count = sum(1 for h in hosts if h["classification"] == "uncertain")
    unknown_count = sum(1 for h in hosts if h["classification"] == "unknown")

    subnets_swept = ", ".join(ACTIVE_SCOPES)
    notes = [
        f"{len(hosts)} live host(s) found on {subnets_swept}: {iot_count} classified as IoT "
        f"appliance(s), {uncertain_count} uncertain, {unknown_count} unclassifiable from the scanned "
        "signature ports alone.",
        "Classification uses only the open-port/service signature (a management UI or MQTT port = "
        "IoT; Telnet/SSH alone = uncertain, since those protocols are common to non-IoT network "
        "appliances too). MAC address + vendor (from a maintained IEEE OUI registry, falling back to "
        "nmap's own bundled guess) is captured as corroborating evidence where nmap's own ARP-based "
        "host discovery resolved one, but is not used to drive the classification itself: this scan "
        "runs from inside a Docker bridge network, where every container shares the host kernel and "
        "uses a virtual, locally-administered MAC address, so a null/'Unknown' vendor here is the "
        "correct, expected result in this lab, not a lookup failure. OS/TTL fingerprinting is still "
        "not used as a corroborating signal for the same reason. On a real physical VLAN, MAC vendor "
        "data will genuinely help distinguish device types; treat it as additional evidence there, not "
        "as the sole basis for a classification.",
    ]
    if uncertain_count:
        notes.append(
            "Do not treat an 'uncertain' host as confirmed non-IoT - it means the signature set was "
            "inconclusive, not that the host was ruled out. Confirm manually (banner-grab the open "
            "port, check the vendor's documentation) before excluding it from the device inventory.",
        )
    new_from_broadcast = sum(1 for h in hosts if h["discovery_signals"] == ["upnp_broadcast"] or h["discovery_signals"] == ["mdns_broadcast"])
    if new_from_broadcast:
        notes.append(
            f"{new_from_broadcast} host(s) were found only via a UPnP/SSDP or mDNS broadcast query, with "
            "no TCP signature port open at all in this sweep's port list - the exact UDP-only-device gap "
            "this broadcast fold-in closes.",
        )

    return {
        "subnets": list(ACTIVE_SCOPES),
        "hosts": hosts,
        "iot_device_count": iot_count,
        "uncertain_count": uncertain_count,
        "unknown_count": unknown_count,
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
        # How many of the chained --next responses actually came back - a
        # dropped connection mid-chain would silently truncate `chunks`
        # below len(tried), under-reporting which pairs were even tried.
        # credentials_tried is always the full static list regardless, so
        # this is the only signal that lets suggest_confidence tell "we
        # tried all 10" from "the chain got cut short" apart.
        "chunks_received": len(chunks),
        "notes": notes,
    }


def _suggest_confidence_default_creds(observations: dict) -> str:
    tried = observations.get("credentials_tried") or []
    if observations.get("chunks_received", len(tried)) < len(tried):
        return "medium"
    return "high"


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


def _tamper_status_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme)
    authority = _authority_for(target, scheme)
    return ["curl", *flags, f"{scheme}://{authority}/api/status"]


def _parse_tamper_status_observations(target: dict, output: str) -> dict:
    wired_match = re.search(r'"tamper_detection_wired"\s*:\s*(true|false)', output, re.IGNORECASE)
    tamper_detection_wired = bool(wired_match) and wired_match.group(1).lower() == "true"
    if wired_match and not tamper_detection_wired:
        notes = [
            "This device reports no hardware tamper-detection mechanism wired "
            "up - physical tampering or removal would go undetected.",
        ]
    elif wired_match:
        notes = ["Hardware tamper detection is reported as wired up on this device."]
    else:
        notes = ["This endpoint did not report a tamper-detection status."]
    return {"tamper_detection_wired": tamper_detection_wired, "notes": notes}


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
        # Same rationale as _parse_login_observations: a dropped connection
        # mid-chain would leave chunks short of 2, silently defaulting
        # dashboard_accessible_without_session to False rather than
        # genuinely observing it - suggest_confidence needs to see this.
        "chunks_received": len(chunks),
        "notes": notes,
    }


def _suggest_confidence_session(observations: dict) -> str:
    if observations.get("chunks_received", 2) < 2:
        return "medium"
    return "high"


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


def _suggest_confidence_http_inspect(observations: dict) -> str:
    # A genuinely absent Server header and a request that failed to get any
    # response back look identical here (both leave server_banner None) -
    # can't tell "the header just isn't set" from "we didn't get anything".
    if observations.get("server_banner") is None:
        return "medium"
    return "high"


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

PROTOCOL_PROBE_RE = re.compile(r"^(TLSv1(?:\.[123])?)=(accepted|rejected|untestable)$", re.MULTILINE)


def _parse_protocol_probe(output: str) -> dict[str, bool | None]:
    """Parses tls_cert_check.py's PROTOCOL_PROBE_START/...END block into
    {"TLSv1": False, "TLSv1.1": None, "TLSv1.2": True, "TLSv1.3": True} -
    True/False only for a real accepted/rejected handshake outcome, None
    when this host's own OpenSSL build couldn't even attempt that version
    (never guessed as True or False)."""
    return {label: ({"accepted": True, "rejected": False}.get(outcome)) for label, outcome in PROTOCOL_PROBE_RE.findall(output)}


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

    protocol_probe = _parse_protocol_probe(output)
    supported_tls_versions = [label for label, accepted in protocol_probe.items() if accepted]
    deprecated_accepted = any(protocol_probe.get(v) for v in DEPRECATED_TLS_VERSIONS if v in protocol_probe)
    untestable_versions = [label for label, accepted in protocol_probe.items() if accepted is None]

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
    if deprecated_accepted:
        notes.append(
            "This server accepted a forced handshake at a deprecated protocol "
            "version (TLSv1/TLSv1.1), even if a stronger version is what "
            "gets negotiated by default - deprecated versions should be "
            "disabled server-side, not just left unused.",
        )
    if cert_expired:
        notes.append("The certificate has expired - reissue it before it is used to accept a real connection.")
    elif cert_expired is None:
        notes.append("Could not determine certificate expiry from the handshake output.")
    if untestable_versions:
        notes.append(
            f"Could not determine whether the server accepts {', '.join(untestable_versions)} - "
            "this scanning host's own OpenSSL build refuses to offer that "
            "version at all, so its real availability on the server is unknown, "
            "not confirmed absent.",
        )
    if not notes:
        notes.append("No weak key or deprecated protocol version detected.")
    return {
        "tls_version": tls_version,
        "weak_cipher": weak_cipher,
        "cert_expired": cert_expired,
        "protocol_probe": protocol_probe,
        "supported_tls_versions": supported_tls_versions,
        "deprecated_tls_versions_supported": deprecated_accepted,
        "notes": notes,
    }


def _suggest_confidence_tls(observations: dict) -> str:
    if observations.get("cert_expired") is None or observations.get("tls_version") is None:
        return "medium"
    if any(accepted is None for accepted in (observations.get("protocol_probe") or {}).values()):
        return "medium"
    return "high"


PQC_READINESS_CHECK_SCRIPT = "/work/lab/auditor/worker/scan_scripts/pqc_readiness_check.py"

# The 3 hybrid PQC group names below were confirmed live against this
# project's own auditor-worker image (OpenSSL 3.5.6) via `openssl list
# -tls1_3 -tls-groups` (see docs/pqc-readiness.md). A first version also
# included a 4th, invented-by-analogy name, X448MLKEM1024, which does not
# exist in OpenSSL's real hybrid-group registry (ML-KEM-1024 only pairs
# with SecP384r1, not X448) - passing it made `-groups` reject its entire
# argument outright, so every device reported connection_error instead of
# a real result until this was caught by the first live scan and fixed.
PQC_HYBRID_GROUPS = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}
PQC_SIGNATURE_MARKERS = ("ml-dsa", "dilithium", "slh-dsa", "sphincs")


def _pqc_tls_command(target: dict) -> list[str]:
    return ["python3", PQC_READINESS_CHECK_SCRIPT, target["host"], str(target["port"])]


def _parse_pqc_tls_observations(target: dict, output: str) -> dict:
    group_match = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", output)
    negotiated_group = group_match.group(1) if group_match else None
    cert_found = "cert_pem_found=True" in output
    sig_match = re.search(r"Signature Algorithm:\s*(\S+)", output)
    signature_algorithm = sig_match.group(1) if sig_match else None

    # A device with a registered TLS service that's simply unreachable at
    # scan time (real infra flakiness) must read as indeterminate, never a
    # fabricated FAIL - distinct from a real handshake that negotiated a
    # classical group on purpose.
    connection_error = negotiated_group is None and not cert_found

    is_pqc_kem = negotiated_group in PQC_HYBRID_GROUPS if negotiated_group else None
    is_pqc_signature = (
        any(marker in signature_algorithm.lower() for marker in PQC_SIGNATURE_MARKERS)
        if signature_algorithm
        else None
    )

    notes = []
    if connection_error:
        notes.append(
            "Could not complete a TLS handshake against this service to check post-quantum "
            "readiness - the service may be down or unreachable right now.",
        )
    else:
        if is_pqc_kem is False:
            notes.append(TIP_TLS_KEY_EXCHANGE_FAIL)
        elif is_pqc_kem is True:
            notes.append(f"Negotiated a hybrid post-quantum key exchange group ({negotiated_group}).")
        if is_pqc_signature is False:
            notes.append(TIP_CERT_SIGNATURE_FAIL)
        elif is_pqc_signature is True:
            notes.append(f"Certificate is signed with a post-quantum algorithm ({signature_algorithm}).")
    if not cert_found and not connection_error:
        notes.append("Could not extract a certificate from the handshake to check its signature algorithm.")

    return {
        "negotiated_group": negotiated_group,
        "is_pqc_kem": is_pqc_kem,
        "cert_signature_algorithm": signature_algorithm,
        "is_pqc_signature": is_pqc_signature,
        "connection_error": connection_error,
        "notes": notes,
    }


def _suggest_confidence_pqc_tls(observations: dict) -> str:
    return "medium" if observations.get("connection_error") else "high"


TLS_CLIENT_AUTH_CHECK_SCRIPT = "/work/lab/auditor/worker/scan_scripts/tls_client_auth_check.py"


def _tls_client_auth_command(target: dict) -> list[str]:
    return ["python3", TLS_CLIENT_AUTH_CHECK_SCRIPT, target["host"], str(target["port"])]


def _parse_tls_client_auth_observations(target: dict, output: str) -> dict:
    requested = "client_cert_requested=True" in output
    notes = (
        ["The server requests a client certificate during the TLS handshake - peer authentication is in place."]
        if requested
        else [
            "The server never requests a client certificate during the TLS handshake - any TLS "
            "client can connect with no cryptographic peer authentication.",
        ]
    )
    return {"client_cert_requested": requested, "notes": notes}


# Conventional paths checked for each of the next two collectors - a real,
# if inherently heuristic, signal: this lab's own devices only ever expose
# whatever path each one happens to implement (e.g. only device-smartlock
# has /api/access-log), so a "not found" result here means exactly that -
# no endpoint at these specific paths - never a claim that no logging or
# monitoring exists anywhere on the device.
SECURITY_LOG_ENDPOINT_PATHS = ("/api/access-log", "/api/voice-log", "/api/logs")
MONITORING_ENDPOINT_PATHS = ("/health", "/metrics", "/status")


def _chained_path_probe_command(target: dict, paths: tuple[str, ...]) -> list[str]:
    scheme = _scheme_for(target)
    authority = _authority_for(target, scheme)
    command: list[str] = ["curl"]
    for index, path in enumerate(paths):
        if index > 0:
            command.append("--next")
        command += _http_flags(scheme, "-o", "/dev/null", "-w", f"{path} %{{http_code}}\n")
        command.append(f"{scheme}://{authority}{path}")
    return command


def _parse_path_probe_observations(output: str, paths: tuple[str, ...]) -> tuple[bool, list[str]]:
    found = re.findall(r"(\S+) 200", output)
    return bool(found), found


def _security_log_endpoint_command(target: dict) -> list[str]:
    return _chained_path_probe_command(target, SECURITY_LOG_ENDPOINT_PATHS)


def _parse_security_log_endpoint_observations(target: dict, output: str) -> dict:
    present, found_paths = _parse_path_probe_observations(output, SECURITY_LOG_ENDPOINT_PATHS)
    notes = (
        [f"A security/access-log endpoint was found at {', '.join(found_paths)} - confirm it is access-controlled."]
        if present
        else [f"No conventional security/access-log endpoint (checked: {', '.join(SECURITY_LOG_ENDPOINT_PATHS)}) was found."]
    )
    return {"security_log_endpoint_present": present, "found_paths": found_paths, "notes": notes}


def _monitoring_endpoint_command(target: dict) -> list[str]:
    return _chained_path_probe_command(target, MONITORING_ENDPOINT_PATHS)


def _parse_monitoring_endpoint_observations(target: dict, output: str) -> dict:
    present, found_paths = _parse_path_probe_observations(output, MONITORING_ENDPOINT_PATHS)
    notes = (
        [f"A diagnostic/monitoring endpoint was found at {', '.join(found_paths)}."]
        if present
        else [f"No conventional diagnostic/monitoring endpoint (checked: {', '.join(MONITORING_ENDPOINT_PATHS)}) was found."]
    )
    return {"monitoring_endpoint_present": present, "found_paths": found_paths, "notes": notes}


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


def _advisory_from_grype_matches(name: str, version: str, matches: list[dict]) -> dict:
    fixed = [m for m in matches if m.get("fix_state") == "fixed" and m.get("fix_versions")]
    patched_version = fixed[0]["fix_versions"][0] if fixed else None
    kev_count = sum(1 for m in matches if m.get("kev_listed"))
    cves = sorted(
        (
            {
                "id": m["id"], "cvss": m.get("cvss"), "summary": m.get("summary") or "",
                "kev_listed": bool(m.get("kev_listed")),
                "kev_date_added": m.get("kev_date_added"),
            }
            for m in matches
        ),
        # KEV-listed findings first (a real exploitation record outranks a
        # merely-high CVSS score), then by CVSS within each group.
        key=lambda c: (c["kev_listed"], c["cvss"] or 0),
        reverse=True,
    )
    return {
        "name": name,
        "version": version,
        "outdated": patched_version is not None,
        "eol": None,
        "latest_known_version": None,
        "official_patch_available": patched_version is not None,
        "patched_version": patched_version,
        "kev_listed_count": kev_count,
        "cves": cves,
        "notes": [
            f"{len(cves)} CVE(s) found via Grype's local vulnerability database "
            "(package/version match only - not vendor/model-specific)."
            + (
                f" {kev_count} of these are on CISA's Known Exploited "
                "Vulnerabilities catalog - confirmed exploitation in the wild, "
                "not just a theoretical score."
                if kev_count
                else ""
            ),
        ],
    }


def _clean_grype_advisory(name: str, version: str) -> dict:
    return {
        "name": name,
        "version": version,
        "outdated": False,
        "eol": None,
        "latest_known_version": None,
        "official_patch_available": False,
        "patched_version": None,
        "kev_listed_count": 0,
        "cves": [],
        "notes": ["No CVEs found for this package/version in Grype's local vulnerability database."],
    }


def _parse_fw_manifest_observations(target: dict, output: str) -> dict:
    present = "manifest_present=True" in output
    packages_line = re.search(r"^packages=(.*)$", output, re.MULTILINE)
    grype_line = re.search(r"^grype_result=(.*)$", output, re.MULTILINE)
    grype_ran = grype_line is not None
    grype_matches_by_pkg: dict[tuple[str, str], list[dict]] = {}
    if grype_line and grype_line.group(1):
        try:
            for m in json.loads(grype_line.group(1)):
                grype_matches_by_pkg.setdefault((m["package"], m["version"]), []).append(m)
        except (json.JSONDecodeError, KeyError):
            grype_ran = False
    packages = []
    if present and packages_line and packages_line.group(1):
        for entry in packages_line.group(1).split(","):
            name, _, version = entry.partition(":")
            key = (name, version)
            if key in grype_matches_by_pkg:
                packages.append(_advisory_from_grype_matches(name, version, grype_matches_by_pkg[key]))
                continue
            static = lookup_component(name, version)
            if static["outdated"] is not None:
                packages.append(static)
            elif grype_ran:
                packages.append(_clean_grype_advisory(name, version))
            else:
                packages.append(static)
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
            f"with {cve_count} known CVE(s) found across Grype's local vulnerability "
            "database and this project's own curated reference table.",
        )
    result = {"manifest_present": present, "packages": packages, "notes": notes}
    if grype_ran:
        built_at = re.search(r"^grype_db_built_at=(.*)$", output, re.MULTILINE)
        checksum = re.search(r"^grype_db_checksum=(.*)$", output, re.MULTILINE)
        if built_at and built_at.group(1):
            result["vuln_db_built_at"] = built_at.group(1)
        if checksum and checksum.group(1):
            result["vuln_db_checksum"] = checksum.group(1)
    return result


def _suggest_confidence_fw_manifest(observations: dict) -> str:
    # Absence means Grype didn't run and the result fell back to this
    # project's own small static reference table - the same "less complete"
    # signal vuln_routes.py/the dashboard already treat as real, not new.
    if "vuln_db_built_at" not in observations:
        return "medium"
    return "high"


def _parse_pqc_firmware_observations(target: dict, output: str) -> dict:
    present = "manifest_present=True" in output
    results_line = re.search(r"^pqc_results=(.*)$", output, re.MULTILINE)
    packages = []
    if present and results_line and results_line.group(1):
        try:
            packages = json.loads(results_line.group(1))
        except json.JSONDecodeError:
            packages = []

    notes = []
    if not present:
        notes.append("No firmware manifest was found - this criterion is not yet assessable for this device.")
    else:
        failing = [p for p in packages if p["pqc_status"] == "fail"]
        unknown = [p for p in packages if p["pqc_status"] == "unknown"]
        if failing:
            notes.append(TIP_FIRMWARE_CRYPTO_FAIL)
        if unknown and not failing:
            notes.append(TIP_FIRMWARE_CRYPTO_UNKNOWN)
        if not failing and not unknown and packages:
            notes.append("Every recognized crypto library in this firmware's manifest supports post-quantum cryptography.")

    return {
        "manifest_present": present,
        "packages": packages,
        "notes": notes,
    }


def _suggest_confidence_pqc_firmware(observations: dict) -> str:
    return "high" if observations.get("manifest_present") else "medium"


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


# Device (vendor, model) -> the real NVD CPE 2.3 "part:vendor:product" prefix
# that product is catalogued under. Mirrors the precedent set by
# lab/auditor/worker/scan_scripts/sbom.py's CPE_OVERRIDES: a small,
# hand-verified table for the cases where naive name-lowercasing does not
# produce a real CPE string.
#
# EVERY entry below was verified individually against the live NVD CPE
# dictionary (services.nvd.nist.gov/rest/json/cpes/2.0) and then confirmed to
# return real CVEs from the live CVE API, on 2026-08-06. None were guessed,
# because guessing does not work here - three things the obvious
# "{vendor}:{model}_firmware" convention gets wrong:
#
#   1. The `_firmware` suffix is NOT universal. Axis's M3216-LVE is catalogued
#      only as a HARDWARE CPE (part `h:`) with no firmware product at all -
#      which still returns 6 real CVEs. That is why the value carries the CPE
#      part, not just vendor:product.
#   2. NVD vendor slugs are not the vendor's marketing name lowercased. Yale
#      locks are catalogued under `assaabloy`; Schneider under
#      `schneider-electric` (hyphen).
#   3. Some real products have no CPE coverage at all. Dahua's NVR4108-8P is
#      deliberately ABSENT below (confirmed absent three ways: keyword
#      searches for "nvr4108", "dahua nvr" and "dahua nvr4" return no such
#      product). An honest "no CPE mapping available" for that device is the
#      correct result and the collector reports it as such - inventing a
#      plausible-looking CPE would be exactly the fabrication this project
#      forbids everywhere else.
#
# Keyed by (vendor, model) EXACTLY as stored on devices.vendor/devices.model,
# which for this lab's fixtures is what TEST-DEVICE-ID reads from each
# device's own /api/device/info. Backslash escapes inside a product value are
# NVD's own CPE-component escaping and must be preserved verbatim - they are
# what the live API matches on (confirmed: the Hikvision entry returns 1 CVE
# with them, and would be a different, non-existent product without them).
DEVICE_CPE_OVERRIDES: dict[tuple[str, str], str] = {
    ("Hikvision", "DS-2CD2143G2-I"): r"o:hikvision:ds-2cd2143g2-i\(s\)_firmware",
    ("Hikvision", "DS-2CD2143G2-IU"): r"o:hikvision:ds-2cd2143g2-iu_firmware",
    ("Axis Communications", "M3216-LVE"): r"h:axis:m3216-lve",
    ("Yale", "Conexis L1"): r"o:assaabloy:yale_conexis_l1_firmware",
    ("Schneider Electric", "Modicon M221"): r"o:schneider-electric:modicon_m221_firmware",
    ("Netgear", "R7000"): r"o:netgear:r7000_firmware",
    ("Sonos", "One (Gen 2)"): r"o:sonos:one_firmware",
}


def lookup_device_cpe(vendor: str | None, model: str | None) -> str | None:
    """The one accessor for DEVICE_CPE_OVERRIDES, so an unmapped device always
    produces the same honest miss rather than a KeyError in one caller and a
    guess in another - the discipline vuln_reference.lookup_component()
    already follows for package-level data."""
    if not vendor or not model:
        return None
    return DEVICE_CPE_OVERRIDES.get((vendor, model))


def _device_id_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = _http_flags(scheme)
    authority = _authority_for(target, scheme)
    return ["curl", *flags, f"{scheme}://{authority}/api/device/info"]


def _parse_device_id_observations(target: dict, output: str) -> dict:
    """SA-IOT-001's long-missing collector: reads a device's own
    unauthenticated device-info endpoint for the structured identity fields
    an asset inventory needs.

    `device_identified` is the EXACT field name SA-IOT-001.yaml's pass/fail
    conditions read (observations.device_identified) - it is a pre-existing
    contract dating to Day 3 of this project, not a naming choice. Per that
    control's own `limitations` text, MAC disclosure is deliberately NOT part
    of the pass condition; only vendor + model + firmware_version together
    are. `mac` is still surfaced because an auditor doing inventory wants it,
    it just doesn't decide the verdict.

    Parsed with per-field regexes rather than json.loads(): every other
    collector in this catalog parses defensively out of possibly-noisy
    command output (curl can prepend/append its own text, a device can return
    a partial body), and a JSONDecodeError on one malformed byte would lose
    the fields that DID come back."""
    def _field(name: str) -> str | None:
        match = re.search(rf'"{name}"\s*:\s*"([^"]*)"', output)
        return match.group(1) if match and match.group(1) else None

    vendor = _field("vendor")
    model = _field("model")
    firmware_version = _field("firmware_version")
    device_identified = bool(vendor and model and firmware_version)

    if device_identified:
        notes = [
            "This device exposes vendor, model, and firmware version via an "
            "unauthenticated read-only endpoint - it supports asset inventory "
            "and downstream device-level CVE lookup (TEST-DEVICE-CVE-LOOKUP).",
        ]
    else:
        missing = [
            name for name, value in (
                ("vendor", vendor), ("model", model), ("firmware version", firmware_version),
            ) if not value
        ]
        notes = [
            "No unauthenticated device-info endpoint disclosed "
            f"{', '.join(missing)} - asset inventory for this device must be "
            "completed manually, and device-level CVE lookup cannot run "
            "without a vendor and model.",
        ]
    return {
        "device_identified": device_identified,
        "vendor": vendor,
        "model": model,
        "firmware_version": firmware_version,
        "mac": _field("mac"),
        "notes": notes,
    }


def _suggest_confidence_device_id(observations: dict) -> str:
    # A clean structured read of all three fields is as strong as this
    # collector gets; a partial or absent disclosure is a real observation
    # too, but one an auditor should look at before it hardens into
    # inventory data.
    return "high" if observations.get("device_identified") else "medium"


MAC_VENDOR_CHECK_SCRIPT = "/work/lab/auditor/worker/scan_scripts/mac_vendor_check.py"

# Vendor names never match between a device's own marketing string and an IEEE
# OUI registration - "Hikvision" vs "Hangzhou Hikvision Digital Technology
# Co.,Ltd.", "Yale" vs "Assa Abloy AB - Yale", "Axis Communications" vs "Axis
# Communications AB". Comparing them needs a real rule, not equality.
#
# The rule: strip corporate suffixes and punctuation from both sides, then ask
# whether either normalized name contains the other as a whole-word run. That
# is deliberately conservative in one direction - it can report "no match" for
# a genuine pair whose names share no common token (a rebrand, or an ODM
# manufacturing under another name) - because the alternative, fuzzy scoring,
# would produce a confident-looking number this project has no way to justify.
# An unmatched pair is therefore reported as "review", never as "spoofed".
_CORPORATE_SUFFIXES = (
    "co", "ltd", "limited", "inc", "incorporated", "corp", "corporation",
    "company", "gmbh", "ag", "ab", "sa", "srl", "bv", "nv", "plc", "llc",
    "technology", "technologies", "digital", "electronics", "electric",
    "international", "group", "holdings", "systems", "networks",
)


def _normalize_vendor_name(name: str) -> list[str]:
    """A vendor name reduced to its meaningful tokens, lowercased, with
    punctuation and corporate suffixes dropped."""
    cleaned = re.sub(r"[^a-z0-9]+", " ", (name or "").lower())
    return [token for token in cleaned.split() if token and token not in _CORPORATE_SUFFIXES]


def vendor_names_agree(claimed: str | None, registered: str | None) -> bool | None:
    """True/False when both names are present and comparable, None when the
    comparison cannot be made at all (either side missing, or one reduces to
    no meaningful tokens once suffixes are stripped). None is a real third
    answer, not a soft False - "we could not check" must never render as
    "these disagree"."""
    if not claimed or not registered:
        return None
    claimed_tokens = _normalize_vendor_name(claimed)
    registered_tokens = _normalize_vendor_name(registered)
    if not claimed_tokens or not registered_tokens:
        return None
    claimed_text = " ".join(claimed_tokens)
    registered_text = " ".join(registered_tokens)
    return claimed_text in registered_text or registered_text in claimed_text


def _mac_vendor_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    authority = _authority_for(target, scheme)
    return ["python3", MAC_VENDOR_CHECK_SCRIPT, f"{scheme}://{authority}"]


def _parse_mac_vendor_observations(target: dict, output: str) -> dict:
    """Four genuinely different outcomes, each reported as itself:
      - no MAC disclosed          -> nothing to look up
      - MAC disclosed, unresolved -> OUI not registered, or lookup failed
      - resolved, names agree     -> corroborated identity
      - resolved, names disagree  -> worth a human's attention
    """
    def _line(name: str) -> str | None:
        match = re.search(rf"^{name}=(.*)$", output, re.MULTILINE)
        return match.group(1) if match and match.group(1) else None

    mac = _line("mac")
    claimed_vendor = _line("claimed_vendor")
    oui = _line("oui")
    oui_vendor = _line("oui_vendor")
    oui_source = _line("oui_source")
    lookup_error = _line("lookup_error")
    mac_disclosed = "mac_disclosed=True" in output

    vendor_match = vendor_names_agree(claimed_vendor, oui_vendor)

    notes: list[str] = []
    if not mac_disclosed:
        notes.append(
            "This device's info endpoint disclosed no MAC address, so no OUI "
            "vendor lookup was possible. Asset inventory can still identify it "
            "by vendor/model, but the hardware-level cross-check is "
            "unavailable.",
        )
    elif lookup_error:
        notes.append(
            f"The MAC was extracted ({mac}) but the vendor lookup could not be "
            f"completed: {lookup_error}. This is missing data, not evidence "
            "that the OUI is unregistered - re-run once connectivity is "
            "restored.",
        )
    elif not oui_vendor:
        notes.append(
            f"The OUI {oui} is not registered to any organization in the IEEE "
            "registry or macvendors.com. That is the expected, correct result "
            "for a locally-administered or randomized MAC (including every "
            "Docker-assigned container MAC), and is not by itself suspicious.",
        )
    elif vendor_match is True:
        notes.append(
            f"The MAC prefix {oui} is registered to \"{oui_vendor}\", which "
            f"corroborates this device's own claim to be a {claimed_vendor} "
            "product. Hardware identity and self-reported identity agree.",
        )
    elif vendor_match is False:
        notes.append(
            f"MISMATCH: this device reports itself as \"{claimed_vendor}\", but "
            f"its MAC prefix {oui} is registered to \"{oui_vendor}\". Treat as "
            "a finding to investigate, not a conclusion - the honest readings "
            "range from a relabelled/ODM-manufactured device or a reused NIC "
            "through to a deliberately spoofed identity. Confirm against the "
            "physical asset before recording it as either.",
        )
    else:
        notes.append(
            f"The MAC prefix {oui} resolves to \"{oui_vendor}\", but that name "
            "could not be compared against this device's own claim "
            f"(\"{claimed_vendor or 'none reported'}\") - review the two by eye.",
        )

    return {
        "mac": mac,
        "mac_disclosed": mac_disclosed,
        "oui": oui,
        "claimed_vendor": claimed_vendor,
        "oui_vendor": oui_vendor,
        "oui_source": oui_source,
        "vendor_match": vendor_match,
        "lookup_error": lookup_error,
        "notes": notes,
    }


def _suggest_confidence_mac_vendor(observations: dict) -> str:
    # A resolved OUI is a hard, registry-backed fact. Anything else - no MAC,
    # a failed lookup, or an unregistered OUI - is a weaker observation an
    # auditor should read before it becomes evidence.
    return "high" if observations.get("oui_vendor") else "medium"


DEVICE_CVE_LOOKUP_SCRIPT = "/work/lab/auditor/worker/scan_scripts/device_cve_lookup.py"


def _device_cve_lookup_command(target: dict) -> list[str]:
    return ["python3", DEVICE_CVE_LOOKUP_SCRIPT, target["device_id"]]


def _parse_device_cve_lookup_observations(target: dict, output: str) -> dict:
    """Assembles the device-level CVE advisory at WRITE time, exactly like
    _parse_fw_manifest_observations does for package-level data - the API
    stays a dumb, honest read of whatever the worker already recorded.

    Three genuinely different outcomes, each reported as itself and never
    blurred into "no CVEs found":
      - identity unknown       -> nothing to look up yet, run TEST-DEVICE-ID
      - identity known, no CPE -> this product has no NVD CPE coverage
      - CPE matched            -> a real (possibly empty) CVE list
    """
    def _line(name: str) -> str | None:
        match = re.search(rf"^{name}=(.*)$", output, re.MULTILINE)
        return match.group(1) if match and match.group(1) else None

    vendor = _line("vendor")
    model = _line("model")
    firmware_version = _line("firmware_version")
    cpe = _line("cpe")
    cpe_matched = "cpe_matched=True" in output

    cves: list[dict] = []
    raw_cves = _line("device_cves")
    if raw_cves:
        try:
            cves = json.loads(raw_cves)
        except json.JSONDecodeError:
            cves = []

    index_available = "index_available=True" in output
    error = _line("error")

    # Firmware currency: compare this device's reported version against each
    # CVE's stated affected-version range. CSAF is consulted first where it
    # applies (a vendor's own advisory outranks NVD's transcription of it),
    # falling back to NVD's range whenever CSAF cannot resolve the CVE - so a
    # single advisory_source field records which one actually answered, and
    # there is never a second parallel affected/not-affected concept.
    schneider_csaf_applicable = "schneider_csaf_applicable=True" in output
    try:
        csaf_ranges = json.loads(_line("schneider_csaf_ranges") or "{}")
    except json.JSONDecodeError:
        csaf_ranges = {}

    sources_checked = ["nvd_version_range"]
    if schneider_csaf_applicable:
        sources_checked.append("schneider_csaf")

    for cve in cves:
        # version_range is the raw NVD extraction; it is consumed here and not
        # persisted verbatim into evidence, which keeps the recorded shape the
        # already-established {id, cvss, summary, kev_*} plus the three new
        # decided fields, rather than raw source internals.
        nvd_range = cve.pop("version_range", None)
        csaf_range = csaf_ranges.get(cve.get("id")) if schneider_csaf_applicable else None

        status, fixed = firmware_version_compare.version_status_for_range(
            firmware_version, csaf_range,
        )
        source = "schneider_csaf" if status != firmware_version_compare.STATUS_UNKNOWN else None
        if status == firmware_version_compare.STATUS_UNKNOWN:
            status, fixed = firmware_version_compare.version_status_for_range(
                firmware_version, nvd_range,
            )
            source = "nvd_version_range" if status != firmware_version_compare.STATUS_UNKNOWN else None

        cve["version_status"] = status
        cve["fixed_version"] = fixed
        cve["advisory_source"] = source

    firmware_currency = (
        firmware_version_compare.rollup_firmware_currency(cves, sources_checked)
        if cpe_matched
        else None
    )

    kev_listed = [c for c in cves if c.get("kev_listed")]
    highest_cvss = max(
        (c["cvss"] for c in cves if c.get("cvss") is not None), default=None,
    )

    notes: list[str] = []
    if error:
        notes.append(f"Could not read this device's inventory record: {error}")
    elif not (vendor and model):
        notes.append(
            "This device has no vendor and model recorded yet, so there is "
            "nothing to match against the CVE database - run TEST-DEVICE-ID "
            "(or enter them manually) first.",
        )
    elif not cpe_matched:
        notes.append(
            f"No CPE mapping is available for {vendor} {model}, so no "
            "device-level CVE lookup was performed. This is an honest gap, "
            "not a clean bill of health: the product may simply not be "
            "catalogued in NVD's CPE dictionary. Package-level analysis "
            "(TEST-FW-MANIFEST, needs a firmware archive) is unaffected.",
        )
    elif not index_available:
        notes.append(
            "This device's product IS mapped to a CPE, but the local NVD "
            "cache has not been populated yet - the worker refreshes it out "
            "of band. Re-run this test after the next refresh.",
        )
    elif not cves:
        notes.append(
            f"NVD has no published CVEs for {vendor} {model} at this CPE. "
            "This is a real checked result, not missing data.",
        )
    else:
        notes.append(
            f"{len(cves)} CVE(s) are published against {vendor} {model} at "
            "the device level - matched by vendor/model CPE, with no firmware "
            "image required. Cross-check each against this device's reported "
            f"firmware version ({firmware_version or 'unknown'}): CPE "
            "matching here is product-level, so a listed CVE may already be "
            "fixed in the running firmware.",
        )
        if kev_listed:
            notes.append(
                f"{len(kev_listed)} of them are on CISA's Known Exploited "
                "Vulnerabilities catalog - treat those as actively exploited "
                "in the wild, not theoretical.",
            )
        if firmware_currency:
            notes.append(f"Firmware currency: {firmware_currency['reason']}")

    return {
        "vendor": vendor,
        "model": model,
        "firmware_version": firmware_version,
        "cpe": cpe,
        "cpe_matched": cpe_matched,
        "device_cves": cves,
        "total_device_cves": len(cves),
        "kev_listed_device_cves": len(kev_listed),
        "highest_device_cvss": highest_cvss,
        "firmware_currency": firmware_currency,
        "notes": notes,
    }


def _suggest_confidence_device_cve_lookup(observations: dict) -> str:
    # A matched CPE read against a populated cache is a real, reproducible
    # lookup. Anything else is a partial answer an auditor should read before
    # it becomes evidence.
    return "high" if observations.get("cpe_matched") else "medium"


SCAN_CATALOG = {
    "TEST-NET-REACHABILITY": {
        "label": "Host reachability",
        "tool": "python3 (socket)",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": ALL_SERVICE_TYPES,
        "build_command": _reachability_command,
        "parse_observations": _parse_reachability_observations,
        "pipeline_phase": PIPELINE_PHASE_FINGERPRINTING,
    },
    "TEST-NET-DISCOVERY": {
        "label": "Network discovery (VLAN sweep)",
        "tool": "nmap",
        "tool_version_command": ["nmap", "--version"],
        "category": CATEGORY_NETWORK_DISCOVERY,
        "applicable_service_types": (),
        "build_command": _network_discovery_command,
        "parse_observations": _parse_network_discovery_observations,
        # A whole-subnet sweep is inherently slower than a single-host test,
        # and the deliberately gentle timing (see _network_discovery_command)
        # trades a little more time for going easier on constrained IoT
        # devices - give it real headroom above job_runner.py's default 30s
        # rather than risk a false timeout. job_runner.py reads this key via
        # spec.get("timeout_seconds", COMMAND_TIMEOUT_SECONDS); every other
        # test omits it and keeps the 30s default.
        "timeout_seconds": 90,
    },
    "TEST-NET-PORTSCAN": {
        "label": "Nmap service/port scan",
        "tool": "nmap",
        "tool_version_command": ["nmap", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": ALL_SERVICE_TYPES,
        "build_command": _nmap_command,
        "parse_observations": _parse_nmap_observations,
        "pipeline_phase": PIPELINE_PHASE_FINGERPRINTING,
    },
    "TEST-MODBUS-PROBE": {
        "label": "Modbus TCP discovery",
        "tool": "nmap",
        "tool_version_command": ["nmap", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": MODBUS_SERVICE_TYPES,
        "build_command": _modbus_probe_command,
        "parse_observations": _parse_modbus_probe_observations,
        "pipeline_phase": PIPELINE_PHASE_FINGERPRINTING,
    },
    "TEST-RTSP-PROBE": {
        "label": "RTSP stream authentication",
        "tool": "nmap",
        "tool_version_command": ["nmap", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": RTSP_SERVICE_TYPES,
        "build_command": _rtsp_probe_command,
        "parse_observations": _parse_rtsp_probe_observations,
        "pipeline_phase": PIPELINE_PHASE_FINGERPRINTING,
    },
    "TEST-UPNP-PROBE": {
        "label": "UPnP/SSDP discovery",
        "tool": "python3 (socket)",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": UPNP_SERVICE_TYPES,
        "build_command": _upnp_probe_command,
        "parse_observations": _parse_upnp_probe_observations,
        "pipeline_phase": PIPELINE_PHASE_FINGERPRINTING,
    },
    "TEST-MDNS-PROBE": {
        "label": "mDNS discovery",
        "tool": "python3 (socket)",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": MDNS_SERVICE_TYPES,
        "build_command": _mdns_probe_command,
        "parse_observations": _parse_mdns_probe_observations,
        "pipeline_phase": PIPELINE_PHASE_FINGERPRINTING,
    },
    "TEST-DEVICE-ID": {
        "label": "Device identification",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _device_id_command,
        "parse_observations": _parse_device_id_observations,
        "suggest_confidence": _suggest_confidence_device_id,
        "pipeline_phase": PIPELINE_PHASE_FINGERPRINTING,
    },
    "TEST-DEVICE-MAC-VENDOR": {
        "label": "MAC address vendor lookup",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _mac_vendor_command,
        "parse_observations": _parse_mac_vendor_observations,
        "suggest_confidence": _suggest_confidence_mac_vendor,
        "pipeline_phase": PIPELINE_PHASE_FINGERPRINTING,
    },
    "TEST-AUTH-DEFAULT-CREDS": {
        "label": "Default credentials",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _login_command,
        "parse_observations": _parse_login_observations,
        "suggest_confidence": _suggest_confidence_default_creds,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-HTTP-HEADERS": {
        "label": "HTTP security headers",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _headers_command,
        "parse_observations": _parse_headers_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-AUTH-ANON-ACCESS": {
        "label": "Anonymous access",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _anon_access_command,
        "parse_observations": _parse_anon_access_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-PHYSICAL-TAMPER-STATUS": {
        "label": "Hardware tamper detection status",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _tamper_status_command,
        "parse_observations": _parse_tamper_status_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-AUTH-SESSION": {
        "label": "Weak session behavior",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _session_command,
        "parse_observations": _parse_session_observations,
        "suggest_confidence": _suggest_confidence_session,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-ADMIN-UNAUTH": {
        "label": "Unprotected administrative endpoint",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_WEB_AUTH,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _admin_unauth_command,
        "parse_observations": _parse_admin_unauth_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-NET-HTTP-INSPECT": {
        "label": "HTTP inspection",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _http_inspect_command,
        "parse_observations": _parse_http_inspect_observations,
        "suggest_confidence": _suggest_confidence_http_inspect,
        "pipeline_phase": PIPELINE_PHASE_FINGERPRINTING,
    },
    "TEST-MQTT-OPEN": {
        "label": "MQTT anonymous access",
        "tool": "mosquitto_sub",
        "tool_version_command": ["mosquitto_sub", "--help"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": MQTT_SERVICE_TYPES,
        "build_command": _mqtt_command,
        "parse_observations": _parse_mqtt_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-TLS-CONFIG": {
        "label": "TLS configuration",
        "tool": "openssl",
        "tool_version_command": ["openssl", "version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": TLS_SERVICE_TYPES,
        "build_command": _tls_command,
        "parse_observations": _parse_tls_observations,
        "suggest_confidence": _suggest_confidence_tls,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
        # tls_cert_check.py now makes 6 handshake attempts (the original 2 plus
        # 4 forced-protocol-version probes) instead of 2 - real headroom above
        # job_runner.py's 30s default, same precedent as TEST-NET-DISCOVERY.
        "timeout_seconds": 90,
    },
    "TEST-NET-PKTCAPTURE": {
        "label": "Packet capture",
        "tool": "tcpdump",
        "tool_version_command": ["tcpdump", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _packet_capture_command,
        "parse_observations": _parse_packet_capture_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-TLS-CLIENT-AUTH": {
        "label": "TLS peer authentication",
        "tool": "python3 (openssl)",
        "tool_version_command": ["openssl", "version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": TLS_SERVICE_TYPES,
        "build_command": _tls_client_auth_command,
        "parse_observations": _parse_tls_client_auth_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-PQC-TLS-HANDSHAKE": {
        "label": "Post-quantum TLS readiness",
        "tool": "python3 (openssl)",
        "tool_version_command": ["openssl", "version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": TLS_SERVICE_TYPES,
        "build_command": _pqc_tls_command,
        "parse_observations": _parse_pqc_tls_observations,
        "suggest_confidence": _suggest_confidence_pqc_tls,
        "pipeline_phase": PIPELINE_PHASE_PQC_READINESS,
        # Two handshakes (negotiated group, then a second for the cert's own
        # signature algorithm) - same 2-handshake shape as TEST-TLS-CONFIG,
        # generous headroom above job_runner.py's 30s default for the same
        # reason.
        "timeout_seconds": 60,
    },
    "TEST-SECURITY-LOG-ENDPOINT": {
        "label": "Security/access log endpoint",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _security_log_endpoint_command,
        "parse_observations": _parse_security_log_endpoint_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-MONITORING-ENDPOINT": {
        "label": "Diagnostic monitoring endpoint",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "category": CATEGORY_NETWORK_PROTOCOL,
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _monitoring_endpoint_command,
        "parse_observations": _parse_monitoring_endpoint_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-FW-VERSION": {
        "label": "Version file",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("version"),
        "parse_observations": _parse_fw_version_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-FW-CONFIG": {
        "label": "Configuration files",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("config"),
        "parse_observations": _parse_fw_config_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-FW-SECRETS": {
        "label": "Hard-coded password or secrets",
        "tool": "yara",
        "tool_version_command": ["python3", "-c", "import yara; print(yara.__version__)"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("secrets"),
        "parse_observations": _parse_fw_secrets_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-FW-APIKEY": {
        "label": "API keys",
        "tool": "yara",
        "tool_version_command": ["python3", "-c", "import yara; print(yara.__version__)"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("apikey"),
        "parse_observations": _parse_fw_apikey_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-FW-CERTKEY": {
        "label": "Certificate or key file",
        "tool": "yara",
        "tool_version_command": ["python3", "-c", "import yara; print(yara.__version__)"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("certkey"),
        "parse_observations": _parse_fw_certkey_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
    "TEST-FW-MANIFEST": {
        "label": "Packet manifest",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("manifest"),
        "parse_observations": _parse_fw_manifest_observations,
        "suggest_confidence": _suggest_confidence_fw_manifest,
        "pipeline_phase": PIPELINE_PHASE_VULN_INTELLIGENCE,
    },
    "TEST-DEVICE-CVE-LOOKUP": {
        "label": "Device CVE lookup (NVD, no firmware required)",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        # Not CATEGORY_FIRMWARE - see is_device_intel_test()'s docstring for
        # why that choice would break this test for firmware-less devices,
        # which are the entire point of it.
        "category": CATEGORY_DEVICE_INTEL,
        "applicable_service_types": (),
        "build_command": _device_cve_lookup_command,
        "parse_observations": _parse_device_cve_lookup_observations,
        "suggest_confidence": _suggest_confidence_device_cve_lookup,
        "pipeline_phase": PIPELINE_PHASE_VULN_INTELLIGENCE,
    },
    "TEST-PQC-FIRMWARE-CRYPTO": {
        "label": "Post-quantum firmware crypto currency",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("pqc_crypto"),
        "parse_observations": _parse_pqc_firmware_observations,
        "suggest_confidence": _suggest_confidence_pqc_firmware,
        "pipeline_phase": PIPELINE_PHASE_PQC_READINESS,
    },
    "TEST-FW-UPDATESCRIPT": {
        "label": "Update script",
        "tool": "python3",
        "tool_version_command": ["python3", "--version"],
        "category": CATEGORY_FIRMWARE,
        "applicable_service_types": (),
        "build_command": _firmware_command("updatescript"),
        "parse_observations": _parse_fw_updatescript_observations,
        "pipeline_phase": PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    },
}


def _default_suggested_finding(observations: dict) -> str:
    """Every parse_observations function above already builds a `notes`
    array that, in the clean/default case, reads as a plain factual finding
    sentence (e.g. "None of the 10 tried default credential pairs were
    accepted.") - joining it is a good suggested finding for every test, no
    per-test finding-text generator needed."""
    notes = observations.get("notes") or []
    return " ".join(notes) or "No automated notes were recorded for this test."


def suggest_finding_and_confidence(test_id: str, observations: dict) -> tuple[str, str]:
    """A suggestion only, computed fresh from already-parsed observations -
    never persisted, never itself written into an evidence record (see
    main.py's record_scan_job_evidence, which still only ever stores what
    the auditor actually submitted). The auditor reviews/edits/confirms
    before anything becomes permanent - this never decides a finding or
    confidence on its own.

    Confidence defaults to "high" for any test with no suggest_confidence
    entry - the least presumptuous default is never guessing a *worse*
    signal than what's actually known, only ever a more honest "medium"
    when a specific field is known to be uncertain."""
    finding = _default_suggested_finding(observations)
    spec = SCAN_CATALOG.get(test_id) or {}
    confidence_fn = spec.get("suggest_confidence")
    confidence = confidence_fn(observations) if confidence_fn else "high"
    return finding, confidence


def is_applicable(target: dict, test_id: str) -> bool:
    spec = SCAN_CATALOG.get(test_id)
    if spec is None:
        return False
    return target.get("service_type") in spec["applicable_service_types"]


def is_firmware_test(test_id: str) -> bool:
    spec = SCAN_CATALOG.get(test_id)
    return spec is not None and spec["category"] == CATEGORY_FIRMWARE


def is_network_discovery_test(test_id: str) -> bool:
    """True for tests that sweep the whole audit-network subnet rather than
    a registered device's host/port - like firmware tests, these carry
    applicable_service_types=() and skip live-target validation entirely
    (see resolve_target() in job_runner.py and _create_scan_job() in
    main.py)."""
    spec = SCAN_CATALOG.get(test_id)
    return spec is not None and spec["category"] == CATEGORY_NETWORK_DISCOVERY


def is_device_intel_test(test_id: str) -> bool:
    """True for tests that reason about a device's already-known identity
    rather than probing it: no live host/port, and - unlike a firmware test -
    no uploaded archive either. The ONLY precondition is that the device is
    registered.

    This distinction is load-bearing, not cosmetic: giving
    TEST-DEVICE-CVE-LOOKUP the firmware category instead would make
    _create_scan_job reject it with "device has no firmware uploaded" for
    precisely the firmware-less devices the device-level CVE lookup exists to
    serve. Like the other two predicates, these carry
    applicable_service_types=() and skip live-target validation entirely."""
    spec = SCAN_CATALOG.get(test_id)
    return spec is not None and spec["category"] == CATEGORY_DEVICE_INTEL
