from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-router-gw"
    # Netgear (Nighthawk family) - grounds the unauthenticated-UPnP/default-
    # creds posture in a real, documented CVE class (CVE-2021-34991,
    # unauthenticated RCE via the UPnP service) plus Netgear's own long
    # default-credential history. Model kept as the bare product number
    # (no space) since it's live-templated into SSDP/UPnP wire-format
    # strings. Illustrative simulation only - not real Netgear firmware,
    # not affiliated with or endorsed by Netgear. See
    # docs/device-vendor-realism.md.
    device_vendor: str = "Netgear"
    device_model: str = "R7000"
    # E0:46:EE is Netgear's real registered IEEE OUI prefix; self-reported
    # only, never consumed by the real network-discovery OUI lookup (see
    # docs/device-vendor-realism.md).
    device_mac: str = "E0:46:EE:00:22:03"
    device_type: str = "router-gateway"
    firmware_version: str = "V1.0.11.132_10.2.132"

    admin_user: str = "admin"
    admin_pass: str = "admin"

    ssdp_port: int = 1900
    ssdp_uuid: str = "38a4a7c0-1111-2222-3333-aabbccddee03"


settings = Settings()
