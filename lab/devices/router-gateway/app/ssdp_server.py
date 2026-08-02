import socket
import threading

from app.config import Settings, settings as default_settings

# A real UPnP IGD responds to ANY unicast or multicast M-SEARCH with no
# authentication - that is the protocol's actual design, not a bug this
# fixture introduces. This models the "answers unauthenticated SSDP queries"
# half of the finding; the other half (accepting arbitrary port-forward
# requests with no auth) lives in main.py's /api/portmap endpoint.
RESPONSE_TEMPLATE = (
    "HTTP/1.1 200 OK\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "EXT:\r\n"
    "LOCATION: http://{host}:80/description.xml\r\n"
    "SERVER: Linux/1.0 UPnP/1.0 {vendor}/{model}\r\n"
    "ST: upnp:rootdevice\r\n"
    "USN: uuid:{uuid}::upnp:rootdevice\r\n"
    "\r\n"
)


def _serve(settings: Settings) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", settings.ssdp_port))
    while True:
        _data, addr = sock.recvfrom(2048)
        # Deliberately does not inspect the request at all - any datagram to
        # this port gets a real device-identifying reply, matching the
        # permissive-by-design posture being modeled.
        reply = RESPONSE_TEMPLATE.format(
            host=addr[0], vendor=settings.device_vendor,
            model=settings.device_model, uuid=settings.ssdp_uuid,
        ).encode()
        sock.sendto(reply, addr)


def start_ssdp_server(settings: Settings = default_settings) -> None:
    thread = threading.Thread(target=_serve, args=(settings,), daemon=True)
    thread.start()
