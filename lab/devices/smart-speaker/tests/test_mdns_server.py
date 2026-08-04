import socket
import time

from app.config import Settings
from app.mdns_server import parse_mdns_txt_record, start_mdns_server


def test_mdns_server_answers_any_datagram_with_unauthenticated_device_details():
    settings = Settings(mdns_port=15353, device_vendor="Sonos", device_model="One (Gen 2)")
    start_mdns_server(settings)
    time.sleep(0.2)  # let the recv loop bind before sending

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", ("127.0.0.1", 15353))
        data, _ = sock.recvfrom(2048)
    finally:
        sock.close()

    parsed = parse_mdns_txt_record(data)
    assert parsed["name"] == "device-speaker.local"
    assert parsed["txt"]["vendor"] == "Sonos"
    assert parsed["txt"]["model"] == "One (Gen 2)"
    assert parsed["txt"]["voice_log_encrypted"] == "false"
