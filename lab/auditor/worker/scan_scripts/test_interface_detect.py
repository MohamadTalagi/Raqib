import socket
from unittest.mock import patch

from lab.auditor.worker.scan_scripts.interface_detect import detect_candidate_subnets


class _Addr:
    def __init__(self, address: str, netmask: str | None, family=socket.AF_INET):
        self.address = address
        self.netmask = netmask
        self.family = family


def _fake_if_addrs(**interfaces: list[_Addr]) -> dict:
    return interfaces


@patch("lab.auditor.worker.scan_scripts.interface_detect.socket.gethostbyname")
@patch("lab.auditor.worker.scan_scripts.interface_detect.psutil.net_if_addrs")
def test_excludes_the_interface_that_resolves_to_the_backend_hostname(mock_addrs, mock_resolve, monkeypatch):
    monkeypatch.setenv("AUDITOR_API_URL", "http://auditor-api:8000")
    mock_addrs.return_value = _fake_if_addrs(
        eth0=[_Addr("172.30.0.5", "255.255.255.0")],
        eth1=[_Addr("172.31.0.5", "255.255.255.0")],
    )
    mock_resolve.return_value = "172.31.0.10"  # falls inside eth1's subnet

    result = detect_candidate_subnets()

    assert result["excluded_backend_subnet"] == "172.31.0.0/24"
    assert result["candidates"] == [{"interface": "eth0", "cidr": "172.30.0.0/24"}]


@patch("lab.auditor.worker.scan_scripts.interface_detect.socket.gethostbyname")
@patch("lab.auditor.worker.scan_scripts.interface_detect.psutil.net_if_addrs")
def test_suggests_every_interface_when_backend_hostname_does_not_resolve(mock_addrs, mock_resolve, monkeypatch):
    monkeypatch.setenv("AUDITOR_API_URL", "http://auditor-api:8000")
    mock_addrs.return_value = _fake_if_addrs(eth0=[_Addr("172.30.0.5", "255.255.255.0")])
    mock_resolve.side_effect = socket.gaierror("no such host")

    result = detect_candidate_subnets()

    assert result["excluded_backend_subnet"] is None
    assert result["candidates"] == [{"interface": "eth0", "cidr": "172.30.0.0/24"}]


@patch("lab.auditor.worker.scan_scripts.interface_detect.psutil.net_if_addrs")
def test_ignores_loopback_and_non_ipv4_addresses(mock_addrs, monkeypatch):
    monkeypatch.setenv("AUDITOR_API_URL", "http://auditor-api:8000")
    mock_addrs.return_value = _fake_if_addrs(
        lo=[_Addr("127.0.0.1", "255.0.0.0")],
        eth0=[_Addr("172.30.0.5", "255.255.255.0")],
        eth0_v6=[_Addr("::1", None, family=socket.AF_INET6)],
    )

    result = detect_candidate_subnets()

    cidrs = [c["cidr"] for c in result["candidates"]]
    assert cidrs == ["172.30.0.0/24"]


@patch("lab.auditor.worker.scan_scripts.interface_detect.psutil.net_if_addrs")
def test_never_raises_when_interface_enumeration_fails(mock_addrs):
    mock_addrs.side_effect = OSError("no network namespace")

    result = detect_candidate_subnets()

    assert result["candidates"] == []
    assert "error" in result
