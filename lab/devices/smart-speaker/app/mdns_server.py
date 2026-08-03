import socket
import struct
import threading

from app.config import Settings, settings as default_settings

MDNS_MULTICAST_GROUP = "224.0.0.251"

# A minimal, hand-rolled DNS response (RFC 1035 wire format) answering ANY
# incoming UDP datagram on 5353 with a TXT record advertising this device's
# identity - real mDNS responders broadcast this kind of detail with no
# authentication by design, and this fixture deliberately never encrypts or
# gates it. Same raw-protocol-probe technique this project already used to
# diagnose the Docker DNS resolver in docs/errors/032.


def _build_response(settings: Settings) -> bytes:
    header = (
        b"\x00\x00"  # ID (unused - this responder doesn't echo the query's ID)
        b"\x84\x00"  # flags: response, authoritative
        b"\x00\x00"  # QDCOUNT
        b"\x00\x01"  # ANCOUNT
        b"\x00\x00"  # NSCOUNT
        b"\x00\x00"  # ARCOUNT
    )
    name = b"\x0edevice-speaker\x05local\x00"
    txt_payload = (
        f"vendor={settings.device_vendor};"
        f"model={settings.device_model};"
        f"voice_log_encrypted={str(settings.voice_log_encrypted).lower()}"
    ).encode()
    rdata = bytes([len(txt_payload)]) + txt_payload
    answer = (
        name
        + b"\x00\x10"  # TYPE = TXT (16)
        + b"\x00\x01"  # CLASS = IN
        + b"\x00\x00\x00\x78"  # TTL = 120
        + len(rdata).to_bytes(2, "big")
        + rdata
    )
    return header + answer


def _serve(settings: Settings) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", settings.mdns_port))
    # A real mDNS responder must join the mDNS multicast group to ever be
    # discoverable via a genuine multicast query (the actual mechanism mDNS
    # uses in the real world) - binding to 0.0.0.0 alone only ever receives
    # unicast/broadcast traffic, never real multicast-addressed datagrams,
    # regardless of any Docker network-level forwarding. Live-confirmed on
    # this project's own worker container: a real multicast PTR query to
    # 224.0.0.251:5353 got zero response before this join, and a real
    # response after it - not a Docker networking limitation, a gap in this
    # fixture's own protocol fidelity. Mirrors ssdp_server.py's identical fix.
    try:
        membership = struct.pack("4s4s", socket.inet_aton(MDNS_MULTICAST_GROUP), socket.inet_aton("0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    except OSError:
        pass  # some sandboxed test environments have no multicast support - unicast still works
    response = _build_response(settings)
    while True:
        _data, addr = sock.recvfrom(2048)
        sock.sendto(response, addr)


def start_mdns_server(settings: Settings = default_settings) -> None:
    thread = threading.Thread(target=_serve, args=(settings,), daemon=True)
    thread.start()


def parse_mdns_txt_record(packet: bytes) -> dict:
    """Decodes the TXT record this responder produces - shared by the
    device's own tests and (via a copy in the worker's collector) the real
    scan-test parser, so both sides agree on the wire format."""
    offset = 12
    labels = []
    while packet[offset] != 0:
        length = packet[offset]
        offset += 1
        labels.append(packet[offset : offset + length].decode())
        offset += length
    offset += 1  # null terminator
    name = ".".join(labels)
    offset += 8  # TYPE + CLASS + TTL
    rdlength = int.from_bytes(packet[offset : offset + 2], "big")
    offset += 2
    txt_length = packet[offset]
    txt = packet[offset + 1 : offset + 1 + txt_length].decode()
    return {"name": name, "txt": dict(pair.split("=", 1) for pair in txt.split(";"))}
