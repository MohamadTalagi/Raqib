import socket
import time

from app.config import Settings
from app.ssdp_server import start_ssdp_server


def test_ssdp_server_answers_any_datagram_with_device_details():
    settings = Settings(ssdp_port=11900, device_vendor="NetCore", device_model="NC-WR1200")
    start_ssdp_server(settings)
    time.sleep(0.2)  # let the recv loop bind before sending

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(b"M-SEARCH * HTTP/1.1\r\n\r\n", ("127.0.0.1", 11900))
        data, _ = sock.recvfrom(2048)
    finally:
        sock.close()

    text = data.decode()
    assert "200 OK" in text
    assert "NetCore" in text
    assert "NC-WR1200" in text
