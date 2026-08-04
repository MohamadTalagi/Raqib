import socket
import time

from app.config import Settings
from app.ssdp_server import _own_ip, start_ssdp_server


def test_ssdp_server_answers_any_datagram_with_device_details():
    settings = Settings(ssdp_port=11900, device_vendor="Netgear", device_model="R7000")
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
    assert "Netgear" in text
    assert "R7000" in text


def test_ssdp_location_header_advertises_the_devices_own_address_not_the_requesters():
    # Real, live-caught bug: LOCATION used to echo the incoming packet's
    # source address (the requester) instead of this device's own address -
    # a real UPnP client (nmap's broadcast-upnp-info, confirmed live) that
    # follows LOCATION to fetch description.xml would get redirected back to
    # itself and fail to connect.
    settings = Settings(ssdp_port=11901, device_vendor="Netgear", device_model="R7000")
    start_ssdp_server(settings)
    time.sleep(0.2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(b"M-SEARCH * HTTP/1.1\r\n\r\n", ("127.0.0.1", 11901))
        data, _ = sock.recvfrom(2048)
    finally:
        sock.close()

    text = data.decode()
    location = [line for line in text.splitlines() if line.upper().startswith("LOCATION")][0]
    # LOCATION must carry this device's own resolved address (whatever
    # _own_ip() genuinely computes on this host), not just happen to match
    # the requester's source address by coincidence.
    assert f"http://{_own_ip()}:80/description.xml" in location
