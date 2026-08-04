from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_page_loads():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Admin" in resp.text


def test_login_success_with_default_creds():
    resp = client.post("/login", data={"username": "admin", "password": "admin"})
    assert resp.status_code == 200


def test_login_fails_with_wrong_creds():
    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_device_info_endpoint():
    resp = client.get("/api/device/info")
    assert resp.status_code == 200
    assert resp.json()["device_type"] == "router-gateway"


def test_portmap_accepts_rule_with_no_authentication():
    resp = client.post(
        "/api/portmap",
        json={"external_port": 9999, "internal_ip": "172.30.0.99", "internal_port": 22},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"

    listed = client.get("/api/portmap").json()["rules"]
    assert any(r["external_port"] == 9999 for r in listed)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_description_xml_completes_the_real_upnp_discovery_flow():
    # A real UPnP client follows ssdp_server.py's LOCATION header here after
    # the initial M-SEARCH response - this endpoint didn't exist at all
    # before this fix, which made that follow-up fetch a real, live-caught
    # dead end for nmap's own broadcast-upnp-info script.
    resp = client.get("/description.xml")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/xml")
    body = resp.text
    assert "<deviceType>" in body and "</UDN>" in body
    assert "<friendlyName>Netgear R7000</friendlyName>" in body
    assert "<manufacturer>Netgear</manufacturer>" in body
    assert "<modelName>R7000</modelName>" in body
