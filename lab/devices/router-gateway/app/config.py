from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-router-gw"
    device_vendor: str = "NetCore"
    device_model: str = "NC-WR1200"
    device_mac: str = "AA:BB:CC:00:22:03"
    device_type: str = "router-gateway"
    firmware_version: str = "4.1.0"

    admin_user: str = "admin"
    admin_pass: str = "admin"

    ssdp_port: int = 1900
    ssdp_uuid: str = "38a4a7c0-1111-2222-3333-aabbccddee03"


settings = Settings()
