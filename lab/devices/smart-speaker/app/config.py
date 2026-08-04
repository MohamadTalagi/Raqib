from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-speaker"
    # Sonos - grounds the unauthenticated-mDNS/unencrypted-voice-log
    # posture in real, documented CVE classes (CVE-2018-11316, unauthenticated
    # UPnP access via DNS rebinding; CVE-2023-50809, unauthenticated RCE
    # enabling covert audio recording). Illustrative simulation only - not
    # real Sonos firmware, not affiliated with or endorsed by Sonos. See
    # docs/device-vendor-realism.md.
    device_vendor: str = "Sonos"
    device_model: str = "One (Gen 2)"
    # 38:42:0B is Sonos's real registered IEEE OUI prefix; self-reported
    # only, never consumed by the real network-discovery OUI lookup (see
    # docs/device-vendor-realism.md).
    device_mac: str = "38:42:0B:00:22:05"
    device_type: str = "smart-speaker"
    firmware_version: str = "15.9"

    mdns_port: int = 5353

    # Raw transcripts, kept forever, never encrypted at rest - the exact
    # CGIoT-1:2024 2-6-2/2-6-3 gap (unprotected data at rest; collecting more
    # than needed with no minimization), from an always-listening angle
    # distinct from the NVR's video-retention scenario.
    voice_log_encrypted: bool = False


settings = Settings()
