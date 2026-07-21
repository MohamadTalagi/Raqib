import socket
import time

from app.config import Settings
from app.telnet_server import start_telnet_server


def test_telnet_server_sends_vendor_model_banner():
    settings = Settings(device_vendor="AcmeCam", device_model="AC-100")
    start_telnet_server(settings)
    time.sleep(0.2)  # let the accept loop bind before connecting

    conn = socket.create_connection(("127.0.0.1", 23), timeout=2)
    try:
        banner = conn.recv(200)
    finally:
        conn.close()

    assert banner == b"AcmeCam AC-100 Telnet Management Console\r\nlogin: "
