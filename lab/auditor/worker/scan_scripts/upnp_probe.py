"""Compound helper for TEST-UPNP-PROBE.

nmap has no per-host UPnP/SSDP script (its UPnP script is broadcast-class,
scoped to a whole subnet, not a single target) - so this is a small,
deterministic raw-UDP probe instead, the same technique this project already
used to diagnose the Docker embedded DNS resolver (docs/errors/032). Sends a
real unicast SSDP M-SEARCH datagram directly to the target's own UPnP port
and reports whatever comes back with no interpretation beyond "did a real
device answer, and what did it say."
"""

import socket
import sys

CONNECT_TIMEOUT_S = 3

SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def main() -> None:
    host, port = sys.argv[1], int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(CONNECT_TIMEOUT_S)
    try:
        sock.sendto(SSDP_REQUEST.encode(), (host, port))
        data, _ = sock.recvfrom(4096)
        print("reachable=True")
        print("response_start")
        print(data.decode(errors="replace"))
        print("response_end")
    except OSError as exc:
        print("reachable=False")
        print(f"error={exc}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
