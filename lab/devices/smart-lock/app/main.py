from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.config import settings

app = FastAPI(title="Smart Lock Device Simulator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory only, matching this lab's other devices - a real audit tool
# reads this from the live API each time, never a stored file the device
# itself owns across restarts.
_state = {"locked": True}
_access_log: list[dict] = []


def _record(action: str, method: str) -> None:
    _access_log.append(
        {
            "action": action,
            "method": method,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )


LOGIN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>Smart Lock</title></head>
<body>
<h1>{vendor} {model} - Access Panel</h1>
<form method="post" action="/login">
  <input type="password" name="pin" placeholder="PIN" />
  <button type="submit">Unlock</button>
</form>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def login_page():
    return LOGIN_PAGE_TEMPLATE.format(vendor=settings.device_vendor, model=settings.device_model)


def _pin_ok(pin: str | None) -> bool:
    if not settings.require_pin_auth:
        return True
    return pin == settings.default_pin


@app.post("/login")
def login(pin: str = ""):
    if pin == settings.default_pin:
        return {"status": "ok", "message": "PIN accepted"}
    raise HTTPException(status_code=401, detail="Invalid PIN")


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


@app.get("/api/status")
def status():
    return {
        "locked": _state["locked"],
        # Always false: this device has no tamper switch wired to anything,
        # so it can never actually report a real intrusion event.
        "tamper_detected": False,
        "tamper_detection_wired": settings.tamper_detection_wired,
    }


@app.post("/api/unlock")
def unlock(x_pin: str | None = Header(default=None)):
    if not _pin_ok(x_pin):
        raise HTTPException(status_code=401, detail="PIN required")
    _state["locked"] = False
    _record("unlock", "pin" if settings.require_pin_auth else "unauthenticated")
    return {"status": "unlocked"}


@app.post("/api/lock")
def lock(x_pin: str | None = Header(default=None)):
    if not _pin_ok(x_pin):
        raise HTTPException(status_code=401, detail="PIN required")
    _state["locked"] = True
    _record("lock", "pin" if settings.require_pin_auth else "unauthenticated")
    return {"status": "locked"}


@app.get("/api/access-log")
def access_log():
    return {"entries": _access_log}


@app.get("/health")
def health():
    return {"status": "healthy"}
