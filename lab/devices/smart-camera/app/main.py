from fastapi import FastAPI, Form, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.config import settings
from app.mqtt_publisher import start_mqtt_publisher

app = FastAPI(title="Smart Camera Device Simulator")

# Wide open on purpose, same as auditor-api: this lab device has no
# authentication boundary to protect with CORS anyway (every endpoint here
# is either intentionally public or gated by REQUIRE_ADMIN_AUTH, not by
# origin). Needed so the dashboard's device console can call these
# endpoints directly from the browser across the :8080 -> :8081/8082/8083
# origin boundary.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
<p><a href="/dashboard">View device dashboard</a></p>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def login_page():
    return LOGIN_PAGE_TEMPLATE.format(vendor=settings.device_vendor, model=settings.device_model)


DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html><head><title>{vendor} {model} - Dashboard</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #14151a; color: #e8e8ea;
          margin: 0; padding: 32px; }}
  .wrap {{ max-width: 640px; margin: 0 auto; }}
  h1 {{ font-size: 20px; margin: 0 0 2px; }}
  .sub {{ color: #8a8f9a; font-size: 13px; margin-bottom: 20px; }}
  .card {{ background: #1c1e24; border: 1px solid #2a2d35; border-radius: 8px; padding: 16px 18px; margin-bottom: 14px; }}
  .card h2 {{ font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #8a8f9a; margin: 0 0 10px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  td {{ padding: 5px 0; border-bottom: 1px solid #2a2d35; }}
  td:first-child {{ color: #8a8f9a; width: 40%; }}
  tr:last-child td {{ border-bottom: none; }}
  .warn {{ color: #f2733c; }}
  button {{ background: #f2a93b; color: #14151a; border: none; border-radius: 6px; padding: 8px 14px;
            font-weight: 600; cursor: pointer; }}
  pre {{ background: #0e0f13; border-radius: 6px; padding: 10px 12px; font-size: 12px; margin-top: 10px;
         white-space: pre-wrap; word-break: break-word; }}
  a {{ color: #f2a93b; }}
</style></head>
<body>
<div class="wrap">
  <h1>{vendor} {model}</h1>
  <div class="sub">{device_id} &middot; posture check for the manual assessment</div>

  <div class="card">
    <h2>Device Info</h2>
    <table>
      <tr><td>MAC address</td><td>{mac}</td></tr>
      <tr><td>Firmware</td><td>{firmware_version}</td></tr>
      <tr><td>Transport</td><td>{transport}</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Config</h2>
    <table>
      <tr><td>Credential mode</td><td>{cred_mode}</td></tr>
      <tr><td>MQTT target</td><td>{mqtt_host} ({mqtt_transport})</td></tr>
      <tr><td>Logging mode</td><td>{logging_mode}</td></tr>
      {api_key_row}
    </table>
  </div>

  <div class="card">
    <h2>Admin</h2>
    <p style="font-size:13px; color:#8a8f9a; margin-top:0;">
      Auth required for reset: <b>{require_admin_auth}</b>
    </p>
    <button onclick="triggerReset()">Trigger admin reset</button>
    <pre id="reset-result"></pre>
  </div>

  <p style="font-size:12px;"><a href="/privacy">Privacy document</a> &middot; <a href="/">Back to login</a></p>
</div>
<script>
  async function triggerReset() {{
    const res = await fetch('/api/admin/reset');
    const body = await res.text();
    document.getElementById('reset-result').textContent = 'HTTP ' + res.status + '\\n' + body;
  }}
</script>
</body></html>"""


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    api_key_row = ""
    if settings.expose_api_key:
        api_key_row = f'<tr><td class="warn">API key (exposed)</td><td class="warn">{settings.api_key}</td></tr>'
    return DASHBOARD_TEMPLATE.format(
        vendor=settings.device_vendor,
        model=settings.device_model,
        device_id=settings.device_id,
        mac=settings.device_mac,
        firmware_version=settings.firmware_version,
        transport=settings.transport.upper(),
        cred_mode=settings.cred_mode,
        mqtt_host=settings.mqtt_host,
        mqtt_transport="TLS" if settings.mqtt_tls else "plaintext",
        logging_mode=settings.logging_mode,
        api_key_row=api_key_row,
        require_admin_auth=settings.require_admin_auth,
    )


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
