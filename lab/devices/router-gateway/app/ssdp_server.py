import socket
import struct
import threading

from app.config import Settings, settings as default_settings

SSDP_MULTICAST_GROUP = "239.255.255.250"

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


def _own_ip() -> str:
    """This device's own real IP, for the LOCATION header - a real UPnP
    device advertises where IT can be reached, never the requester's own
    address. A real, live-caught bug this fixed: the previous version used
    the incoming packet's source address (addr[0]) instead, so any real
    UPnP client - including nmap's own broadcast-upnp-info, confirmed live -
    that follows LOCATION to fetch description.xml got redirected back to
    itself and failed to connect. Falls back to 0.0.0.0 (never raises) if
    hostname resolution is unavailable in some sandboxed test environment -
    the SSDP response itself still succeeds either way."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "0.0.0.0"


def _serve(settings: Settings) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", settings.ssdp_port))
    own_ip = _own_ip()
    # A real UPnP device must join the SSDP multicast group to ever be
    # discoverable via a genuine multicast M-SEARCH (the actual mechanism
    # SSDP discovery uses in the real world) - binding to 0.0.0.0 alone only
    # ever receives unicast/broadcast traffic, never real multicast-addressed
    # datagrams, regardless of any Docker network-level forwarding. Live-
    # confirmed on this project's own worker container: a real multicast
    # M-SEARCH to 239.255.255.250:1900 got zero response before this join,
    # and a real response after it - not a Docker networking limitation, a
    # gap in this fixture's own protocol fidelity.
    try:
        membership = struct.pack("4s4s", socket.inet_aton(SSDP_MULTICAST_GROUP), socket.inet_aton("0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    except OSError:
        pass  # some sandboxed test environments have no multicast support - unicast still works
    while True:
        _data, addr = sock.recvfrom(2048)
        # Deliberately does not inspect the request at all - any datagram to
        # this port gets a real device-identifying reply, matching the
        # permissive-by-design posture being modeled.
        reply = RESPONSE_TEMPLATE.format(
            host=own_ip, vendor=settings.device_vendor,
            model=settings.device_model, uuid=settings.ssdp_uuid,
        ).encode()
        sock.sendto(reply, addr)


def start_ssdp_server(settings: Settings = default_settings) -> None:
    thread = threading.Thread(target=_serve, args=(settings,), daemon=True)
    thread.start()
