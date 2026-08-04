from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False)

    device_id: str = "device-plc-gateway"
    # Schneider Electric Modicon M221 - grounds the unauthenticated-Modbus
    # posture in a real, documented CVE class (CVE-2024-11737, unauthenticated
    # command injection over Modbus TCP port 502). Illustrative simulation
    # only - not real Schneider Electric firmware, not affiliated with or
    # endorsed by Schneider Electric. See docs/device-vendor-realism.md.
    device_vendor: str = "Schneider Electric"
    device_model: str = "Modicon M221"
    # 9C:0E:51 is Schneider Electric's real registered IEEE OUI prefix;
    # self-reported only, never consumed by the real network-discovery OUI
    # lookup (see docs/device-vendor-realism.md).
    device_mac: str = "9C:0E:51:00:22:02"
    device_type: str = "industrial-sensor-gateway"
    firmware_version: str = "SV3.8.1"

    # Modbus TCP has no authentication or encryption in the protocol itself -
    # this is the insecure-by-default posture being modeled (NCA 2-15-2,
    # 2-4-3), not a bug in this fixture.
    modbus_port: int = 502


settings = Settings()
