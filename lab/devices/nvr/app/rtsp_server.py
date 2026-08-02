import re
import socket
import threading

from app.config import Settings, settings as default_settings

# A minimal RTSP/1.0 responder: enough to answer OPTIONS/DESCRIBE the way a
# real camera/NVR stream endpoint would, so nmap-class probes and a real
# RTSP client both get a real protocol handshake. Deliberately answers every
# request with no authentication challenge at all - the finding this fixture
# demonstrates is "the video stream requires no credentials," not a
# simulated encoder.
SDP_BODY = (
    "v=0\r\n"
    "o=- 0 0 IN IP4 0.0.0.0\r\n"
    "s=NVR Live Feed\r\n"
    "t=0 0\r\n"
    "m=video 0 RTP/AVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
)


def _cseq(request: str) -> str:
    match = re.search(r"CSeq:\s*(\S+)", request, re.IGNORECASE)
    return match.group(1) if match else "1"


def _handle_connection(conn: socket.socket) -> None:
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            request = data.decode(errors="replace")
            method = request.split(" ", 1)[0].strip().upper()
            cseq = _cseq(request)

            if method == "DESCRIBE":
                body = SDP_BODY.encode()
                response = (
                    f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                    f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n"
                ).encode() + body
            else:
                # OPTIONS, SETUP, PLAY, TEARDOWN all succeed with no auth check.
                response = (
                    f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                    "Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN\r\n\r\n"
                ).encode()
            conn.sendall(response)
    finally:
        conn.close()


def _serve(settings: Settings) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", settings.rtsp_port))
    server.listen(5)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=_handle_connection, args=(conn,), daemon=True).start()


def start_rtsp_server(settings: Settings = default_settings) -> None:
    thread = threading.Thread(target=_serve, args=(settings,), daemon=True)
    thread.start()
