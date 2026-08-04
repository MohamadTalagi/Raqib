import socket

# Mirrors lab/devices/smart-camera's insecure-profile identity (Hikvision) -
# illustrative simulation only, see docs/device-vendor-realism.md.
BANNER = b"Hikvision Telnet Management Console\r\nlogin: "


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 23))
    server.listen(5)
    while True:
        conn, _ = server.accept()
        try:
            conn.sendall(BANNER)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
