"""Compound helper for TEST-NET-REACHABILITY.

A plain TCP connect() probe - no dedicated CLI tool in this image does just
"can I open a socket to host:port" without also doing something heavier
(nmap already covers port scanning; this is the simpler, single-purpose
reachability check the brief asks for as its own thing). Uses only the
stdlib socket module - no shell, no external command.
"""

import socket
import sys

CONNECT_TIMEOUT_S = 5


def main() -> None:
    host, port = sys.argv[1], int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT_S)
    try:
        sock.connect((host, port))
        print("reachable=True")
    except OSError as exc:
        print("reachable=False")
        print(f"error={exc}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
