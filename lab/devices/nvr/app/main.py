from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.config import settings
from app.rtsp_server import start_rtsp_server

app = FastAPI(title="Network Video Recorder Simulator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Fixed, never-expiring list - models a real NVR that keeps every recorded
# clip with no retention/deletion policy (CGIoT-1:2024 2-6-3).
_clips = [
    {"clip_id": "CLIP-0001", "recorded_at": "2026-01-03T02:14:00Z", "duration_sec": 42},
    {"clip_id": "CLIP-0002", "recorded_at": "2026-01-04T14:02:00Z", "duration_sec": 118},
    {"clip_id": "CLIP-0003", "recorded_at": "2026-02-11T09:47:00Z", "duration_sec": 30},
]


@app.on_event("startup")
def _on_startup():
    start_rtsp_server()


LOGIN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>NVR Admin</title></head>
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


@app.get("/api/clips")
def list_clips():
    return {"clips": _clips, "retention_policy": settings.retention_policy}


@app.get("/health")
def health():
    return {"status": "healthy"}
