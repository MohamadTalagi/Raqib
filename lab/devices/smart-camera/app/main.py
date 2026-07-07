from fastapi import FastAPI, Form, HTTPException, Header
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.config import settings
from app.mqtt_publisher import start_mqtt_publisher

app = FastAPI(title="Smart Camera Device Simulator")


@app.on_event("startup")
def _on_startup():
    start_mqtt_publisher()

LOGIN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>Smart Camera Login</title></head>
<body>
<h1>{vendor} {model} - Login</h1>
<form method="post" action="/login">
  <input type="text" name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def login_page():
    return LOGIN_PAGE_TEMPLATE.format(vendor=settings.device_vendor, model=settings.device_model)


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


@app.get("/api/config")
def get_config():
    config = {
        "cred_mode": settings.cred_mode,
        "mqtt_host": settings.mqtt_host,
        "mqtt_tls": settings.mqtt_tls,
        "logging_mode": settings.logging_mode,
    }
    if settings.expose_api_key:
        # Intentional leak on the insecure profile only (EXPOSE_API_KEY=false elsewhere).
        config["api_key"] = settings.api_key
    return config


@app.post("/api/config")
def update_config(payload: dict):
    return {"status": "accepted", "received": payload}


@app.get("/api/firmware/version")
def firmware_version():
    return {"version": settings.firmware_version}


@app.get("/api/admin/reset")
def admin_reset(authorization: str = Header(default=None)):
    if settings.require_admin_auth:
        expected = f"Bearer {settings.admin_user}:{settings.admin_pass}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="Unauthorized")
    return {"status": "reset-triggered"}


@app.get("/privacy", response_class=PlainTextResponse)
def privacy_doc():
    try:
        with open(settings.privacy_doc_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "No privacy document configured."


@app.get("/health")
def health():
    return {"status": "healthy"}
