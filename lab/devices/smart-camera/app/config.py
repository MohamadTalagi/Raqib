from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-insecure"
    # Vendor/model identify a real, market-relevant product line
    # (Hikvision DS-2CD21xx turret cameras) so scan evidence and the
    # research report can cite a real, documented CVE class (e.g.
    # CVE-2017-7921, a backdoor/privilege-escalation account) instead of a
    # fictional vendor. This is an illustrative simulation only — not real
    # Hikvision firmware, not affiliated with or endorsed by Hikvision. See
    # docs/device-vendor-realism.md.
    device_vendor: str = "Hikvision"
    device_model: str = "DS-2CD2143G2-I"
    # A4:14:37 is Hikvision's real registered IEEE OUI prefix; the
    # last 3 octets are this lab's own numbering. Self-reported only -
    # never consumed by the real OUI/vendor-lookup path, which resolves
    # nmap's ARP-discovered Docker-virtual MAC instead (see
    # docs/device-vendor-realism.md).
    device_mac: str = "A4:14:37:00:11:22"
    device_type: str = "smart-camera"
    firmware_version: str = "V5.3.0 build 160530"

    transport: str = "http"  # http | https — mirrors entrypoint.sh's TRANSPORT env var
    cred_mode: str = "default"  # default | strong
    admin_user: str = "admin"
    admin_pass: str = "admin"

    expose_api_key: bool = True
    # Intentional training fixture for the sandboxed insecure device profile —
    # never a real credential; overridden to empty/unused on partial & hardened.
    api_key: str = "sk-insecure-hardcoded-key-000111222"

    require_admin_auth: bool = False

    # Unencrypted legacy management service - part of the insecure profile's
    # original posture (default off; only insecure.env turns it on).
    telnet_enabled: bool = False

    logging_mode: str = "off"  # off | basic | security

    privacy_doc_path: str = "docs/privacy_insecure.md"

    mqtt_host: str = "mqtt-broker-insecure"
    mqtt_port: int = 1883
    mqtt_tls: bool = False
    mqtt_ca_cert: str = ""


settings = Settings()
