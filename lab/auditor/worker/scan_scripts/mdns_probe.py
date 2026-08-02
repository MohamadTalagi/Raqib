"""Compound helper for TEST-MDNS-PROBE.

Same rationale as upnp_probe.py: no nmap NSE script queries a single host's
mDNS responder directly, so this sends a real DNS-format PTR query
(RFC 1035 wire format, for "_services._dns-sd._udp.local") as a plain unicast
UDP datagram to the target's own port 5353. The response is arbitrary binary
DNS data, not safe to print as text, so it is emitted as hex for
scan_tests.py's parser to decode.
"""

import socket
import sys

CONNECT_TIMEOUT_S = 3

_HEADER = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
_QNAME = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
_QTYPE_PTR = b"\x00\x0c"
_QCLASS_IN = b"\x00\x01"
DNS_QUERY = _HEADER + _QNAME + _QTYPE_PTR + _QCLASS_IN


def main() -> None:
    host, port = sys.argv[1], int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(CONNECT_TIMEOUT_S)
    try:
        sock.sendto(DNS_QUERY, (host, port))
        data, _ = sock.recvfrom(4096)
        print("reachable=True")
        print(f"response_hex={data.hex()}")
    except OSError as exc:
        print("reachable=False")
        print(f"error={exc}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
