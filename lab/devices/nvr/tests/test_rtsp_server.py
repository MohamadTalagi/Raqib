import socket
import time

from app.config import Settings
from app.rtsp_server import start_rtsp_server


def test_rtsp_server_answers_options_with_no_authentication():
    settings = Settings(rtsp_port=15540)
    start_rtsp_server(settings)
    time.sleep(0.2)  # let the accept loop bind before connecting

    conn = socket.create_connection(("127.0.0.1", 15540), timeout=2)
    try:
        conn.sendall(b"OPTIONS rtsp://127.0.0.1:15540/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        response = conn.recv(4096).decode()
    finally:
        conn.close()

    assert "200 OK" in response
    assert "PLAY" in response


def test_rtsp_server_describe_returns_sdp_with_no_authentication():
    settings = Settings(rtsp_port=15541)
    start_rtsp_server(settings)
    time.sleep(0.2)

    conn = socket.create_connection(("127.0.0.1", 15541), timeout=2)
    try:
        conn.sendall(b"DESCRIBE rtsp://127.0.0.1:15541/stream RTSP/1.0\r\nCSeq: 2\r\n\r\n")
        response = conn.recv(4096).decode()
    finally:
        conn.close()

    assert "200 OK" in response
    assert "application/sdp" in response
