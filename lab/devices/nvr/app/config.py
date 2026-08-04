from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-nvr"
    # Dahua - grounds the unauthenticated-RTSP-stream/default-creds posture
    # in real, documented CVE classes (CVE-2021-33045, full NVR/DVR/XVR
    # authentication bypass; CVE-2013-3612, static Telnet root password).
    # Illustrative simulation only - not real Dahua firmware, not
    # affiliated with or endorsed by Dahua. See
    # docs/device-vendor-realism.md.
    device_vendor: str = "Dahua"
    device_model: str = "NVR4108-8P"
    # 14:A7:8B is Dahua's real registered IEEE OUI prefix; self-reported
    # only, never consumed by the real network-discovery OUI lookup (see
    # docs/device-vendor-realism.md).
    device_mac: str = "14:A7:8B:00:22:04"
    device_type: str = "network-video-recorder"
    firmware_version: str = "3.218.0000019.0"

    admin_user: str = "admin"
    admin_pass: str = "admin"

    rtsp_port: int = 554
    # No retention policy at all - clips accumulate forever. Models
    # CGIoT-1:2024 2-6-3 (collecting/retaining data with no minimization).
    retention_policy: str = "none"


settings = Settings()
