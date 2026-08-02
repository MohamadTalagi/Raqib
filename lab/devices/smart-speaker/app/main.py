from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.mdns_server import start_mdns_server

app = FastAPI(title="Smart Speaker Device Simulator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Raw transcripts, never redacted or encrypted - kept indefinitely, matching
# a real "always listening" device's local log with no data-minimization
# control. This is the deliberate flaw, not a placeholder to fill in later.
_voice_log = [
    {
        "timestamp": "2026-01-05T08:12:00Z",
        "transcript": "set a timer for ten minutes",
    },
    {
        "timestamp": "2026-01-06T19:44:00Z",
        "transcript": "what's my bank account balance",
    },
]


@app.on_event("startup")
def _on_startup():
    start_mdns_server()


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


@app.get("/api/voice-log")
def voice_log():
    return {"entries": _voice_log, "encrypted_at_rest": settings.voice_log_encrypted}


@app.post("/api/voice-log")
def record_voice_command(payload: dict):
    _voice_log.append(
        {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "transcript": payload.get("transcript", ""),
        }
    )
    return {"status": "recorded"}


@app.get("/health")
def health():
    return {"status": "healthy"}
