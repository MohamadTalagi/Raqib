from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.modbus_server import start_modbus_server

app = FastAPI(title="Industrial Sensor Gateway Simulator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _on_startup():
    start_modbus_server()


@app.get("/api/device/info")
def device_info():
    return {
        "device_id": settings.device_id,
        "vendor": settings.device_vendor,
        "model": settings.device_model,
        "mac": settings.device_mac,
        "device_type": settings.device_type,
        "firmware_version": settings.firmware_version,
        "modbus_port": settings.modbus_port,
    }


@app.get("/health")
def health():
    return {"status": "healthy"}
