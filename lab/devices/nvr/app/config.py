from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-nvr"
    device_vendor: str = "ViewKeep"
    device_model: str = "VK-NVR8"
    device_mac: str = "AA:BB:CC:00:22:04"
    device_type: str = "network-video-recorder"
    firmware_version: str = "3.0.2"

    admin_user: str = "admin"
    admin_pass: str = "admin"

    rtsp_port: int = 554
    # No retention policy at all - clips accumulate forever. Models
    # CGIoT-1:2024 2-6-3 (collecting/retaining data with no minimization).
    retention_policy: str = "none"


settings = Settings()
