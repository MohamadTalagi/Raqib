"""Network Scope's "Detect automatically" action: inspects auditor-worker's
own network interfaces and suggests which one(s) likely sit on the
customer's IoT network, as opposed to the backend. Reuses the exact same
network_scans row/poll machinery TEST-NET-DISCOVERY's subnet sweep already
uses - job_runner.py's process_network_scan branches on scan["kind"], and
this is a one-shot worker-side action reported back through that same
network_scans.observations column, not a new mechanism.

The heuristic: this container's own interfaces are enumerated, the backend
API's hostname is resolved to find which interface (if any) is the backend
side, and every *other* interface's subnet is suggested as a candidate. This
generalizes past the lab - in a real deployment the worker is expected to
have a leg on the customer's IoT VLAN the same way it has a leg on
audit-network here, and the backend-exclusion logic works identically
whether there are 1, 2, or more interfaces.

Never raises: interface enumeration or hostname resolution can fail for
reasons outside this code's control (a container with no network yet, a
DNS hiccup), and an honest empty/error result is always preferable to a
guessed one - the same rule this project's other collectors follow
(record-failure -> INCONCLUSIVE, never a fabricated pass/fail).
"""

import ipaddress
import os
import socket

import psutil

API_URL_ENV = "AUDITOR_API_URL"
DEFAULT_API_URL = "http://auditor-api:8000"


def _backend_hostname() -> str:
    # "http://auditor-api:8000" -> "auditor-api"
    api_url = os.environ.get(API_URL_ENV, DEFAULT_API_URL)
    return api_url.split("//", 1)[-1].split(":", 1)[0].split("/", 1)[0]


def _local_ipv4_networks() -> list[tuple[str, ipaddress.IPv4Network]]:
    """One (interface_name, network) pair per non-loopback IPv4 address this
    container currently has, sized from the address's own real netmask
    (never a fixed prefix assumption), so this works for whatever subnet
    size a real deployment actually uses."""
    networks = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family != socket.AF_INET or not addr.netmask:
                continue
            if addr.address.startswith("127."):
                continue
            try:
                network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            except ValueError:
                continue
            networks.append((interface, network))
    return networks


def detect_candidate_subnets() -> dict:
    """Returns
    {"candidates": [{"interface": str, "cidr": str}, ...], "excluded_backend_subnet": str | None}
    on success, or {"candidates": [], "error": str} if interface enumeration
    itself failed outright (resolution failure alone is not fatal - it just
    means every local interface gets suggested, since there's nothing to
    exclude)."""
    try:
        local_networks = _local_ipv4_networks()
    except Exception as exc:  # noqa: BLE001 - report, never crash the caller over this
        return {"candidates": [], "error": f"could not enumerate network interfaces: {exc}"}

    backend_network: ipaddress.IPv4Network | None = None
    try:
        backend_ip = ipaddress.ip_address(socket.gethostbyname(_backend_hostname()))
        for _interface, network in local_networks:
            if backend_ip in network:
                backend_network = network
                break
    except (socket.gaierror, ValueError):
        backend_network = None

    seen: set[str] = set()
    candidates = []
    for interface, network in local_networks:
        if network == backend_network:
            continue
        cidr = str(network)
        if cidr in seen:
            continue
        seen.add(cidr)
        candidates.append({"interface": interface, "cidr": cidr})

    return {
        "candidates": candidates,
        "excluded_backend_subnet": str(backend_network) if backend_network else None,
    }
