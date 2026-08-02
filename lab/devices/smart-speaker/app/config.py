from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-speaker"
    device_vendor: str = "VoxHome"
    device_model: str = "VH-Speaker-2"
    device_mac: str = "AA:BB:CC:00:22:05"
    device_type: str = "smart-speaker"
    firmware_version: str = "1.2.0"

    mdns_port: int = 5353

    # Raw transcripts, kept forever, never encrypted at rest - the exact
    # CGIoT-1:2024 2-6-2/2-6-3 gap (unprotected data at rest; collecting more
    # than needed with no minimization), from an always-listening angle
    # distinct from the NVR's video-retention scenario.
    voice_log_encrypted: bool = False


settings = Settings()
