import socket
import threading

from app.config import Settings, settings as default_settings

BANNER_TEMPLATE = "{vendor} {model} Telnet Management Console\r\nlogin: "


def _serve(settings: Settings) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 23))
    server.listen(5)
    banner = BANNER_TEMPLATE.format(vendor=settings.device_vendor, model=settings.device_model).encode()
    while True:
        conn, _ = server.accept()
        try:
            conn.sendall(banner)
        finally:
            conn.close()


def start_telnet_server(settings: Settings = default_settings) -> None:
    thread = threading.Thread(target=_serve, args=(settings,), daemon=True)
    thread.start()
