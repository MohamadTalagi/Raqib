from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-smartlock"
    device_vendor: str = "BoltGuard"
    device_model: str = "BG-200"
    device_mac: str = "AA:BB:CC:00:22:01"
    device_type: str = "smart-lock"
    firmware_version: str = "1.0.0"

    # Training fixture only - never a real PIN. Insecure posture: the device
    # ships with this PIN and nothing forces it to change on first boot,
    # mirroring the camera profile's default-credentials flaw (NCA 2-2-2).
    default_pin: str = "0000"
    require_pin_auth: bool = False

    # Always false regardless of real state - this device never actually
    # wires up its tamper switch to anything, the exact "hardware tamper
    # protection and detection measures" gap CGIoT-1:2024 2-13-2 calls out.
    tamper_detection_wired: bool = False


settings = Settings()
