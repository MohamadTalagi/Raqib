from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-plc-gateway"
    device_vendor: str = "IndustraLink"
    device_model: str = "IL-Gateway-9"
    device_mac: str = "AA:BB:CC:00:22:02"
    device_type: str = "industrial-sensor-gateway"
    firmware_version: str = "2.3.1"

    # Modbus TCP has no authentication or encryption in the protocol itself -
    # this is the insecure-by-default posture being modeled (NCA 2-15-2,
    # 2-4-3), not a bug in this fixture.
    modbus_port: int = 502


settings = Settings()
