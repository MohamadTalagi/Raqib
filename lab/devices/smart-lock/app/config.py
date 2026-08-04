from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-smartlock"
    # Yale Conexis L1 - grounds the default-PIN/unauthenticated-unlock
    # posture in a real, documented CVE class (CVE-2023-26941/26942, a
    # PIN-verification bypass). Illustrative simulation only - not real
    # Yale firmware, not affiliated with or endorsed by Yale/ASSA ABLOY.
    # See docs/device-vendor-realism.md.
    device_vendor: str = "Yale"
    device_model: str = "Conexis L1"
    # B0:44:9C is Yale/ASSA ABLOY's real registered IEEE OUI prefix;
    # self-reported only, never consumed by the real network-discovery OUI
    # lookup (see docs/device-vendor-realism.md).
    device_mac: str = "B0:44:9C:00:22:01"
    device_type: str = "smart-lock"
    firmware_version: str = "1.4.2"

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
