from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response

from app.config import settings
from app.ssdp_server import start_ssdp_server

app = FastAPI(title="Router/Gateway Device Simulator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory port-forward table, seeded empty. Modeled after a real UPnP IGD's
# AddPortMapping action, which most consumer routers historically accept
# from any LAN client with zero authentication (the well-known UPnP
# port-mapping exposure class this fixture demonstrates).
_port_map: list[dict] = []


@app.on_event("startup")
def _on_startup():
    start_ssdp_server()


LOGIN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>Router Admin</title></head>
<body>
<h1>{vendor} {model} - Admin</h1>
<form method="post" action="/login">
  <input type="text" name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
<p style="font-size:11px;color:#888;">Simulated device for security research &mdash; not affiliated with or endorsed by {vendor}.</p>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def login_page():
    return LOGIN_PAGE_TEMPLATE.format(vendor=settings.device_vendor, model=settings.device_model)


# The real device-description document a UPnP client (or nmap's own
# broadcast-upnp-info) fetches after following the SSDP response's LOCATION
# header - completing the real discovery flow ssdp_server.py's response
# advertises but, until this endpoint existed, never actually served.
DESCRIPTION_XML_TEMPLATE = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>{vendor} {model}</friendlyName>
    <manufacturer>{vendor}</manufacturer>
    <modelDescription>{vendor} {model} residential gateway</modelDescription>
    <modelName>{model}</modelName>
    <modelNumber>1</modelNumber>
    <UDN>uuid:{uuid}</UDN>
  </device>
</root>"""


@app.get("/description.xml")
def description_xml():
    body = DESCRIPTION_XML_TEMPLATE.format(
        vendor=settings.device_vendor, model=settings.device_model, uuid=settings.ssdp_uuid,
    )
    return Response(content=body, media_type="text/xml")


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == settings.admin_user and password == settings.admin_pass:
        return {"status": "ok", "message": "Login successful"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/device/info")
def device_info():
    return {
        "device_id": settings.device_id,
        "vendor": settings.device_vendor,
        "model": settings.device_model,
        "mac": settings.device_mac,
        "device_type": settings.device_type,
        "firmware_version": settings.firmware_version,
    }


@app.get("/api/portmap")
def list_portmap():
    return {"rules": _port_map}


@app.post("/api/portmap")
def add_portmap(payload: dict):
    # No authentication check at all, mirroring a real permissive UPnP IGD -
    # any LAN-adjacent caller (this device's actual attack surface) can open
    # an arbitrary forward with no credentials.
    rule = {
        "external_port": payload.get("external_port"),
        "internal_ip": payload.get("internal_ip"),
        "internal_port": payload.get("internal_port"),
    }
    _port_map.append(rule)
    return {"status": "accepted", "rule": rule}


@app.get("/health")
def health():
    return {"status": "healthy"}
