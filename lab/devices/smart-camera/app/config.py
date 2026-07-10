from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-insecure"
    device_vendor: str = "AcmeCam"
    device_model: str = "AC-100"
    device_mac: str = "AA:BB:CC:00:11:22"
    device_type: str = "smart-camera"
    firmware_version: str = "1.0.0-old"

    transport: str = "http"  # http | https — mirrors entrypoint.sh's TRANSPORT env var
    cred_mode: str = "default"  # default | strong
    admin_user: str = "admin"
    admin_pass: str = "admin"

    expose_api_key: bool = True
    # Intentional training fixture for the sandboxed insecure device profile —
    # never a real credential; overridden to empty/unused on partial & hardened.
    api_key: str = "sk-insecure-hardcoded-key-000111222"

    require_admin_auth: bool = False

    logging_mode: str = "off"  # off | basic | security

    privacy_doc_path: str = "docs/privacy_insecure.md"

    mqtt_host: str = "mqtt-broker-insecure"
    mqtt_port: int = 1883
    mqtt_tls: bool = False
    mqtt_ca_cert: str = ""


settings = Settings()
