import certifi

from app.config import Settings
from app.mqtt_publisher import build_client


def test_build_client_uses_device_id_as_client_id():
    settings = Settings(device_id="device-partial")
    client = build_client(settings)
    assert client._client_id.decode() == "device-partial"


def test_build_client_enables_tls_when_configured():
    settings = Settings(mqtt_tls=True, mqtt_ca_cert=certifi.where())
    client = build_client(settings)
    # paho stores the SSL context once tls_set() succeeds
    assert client._ssl_context is not None


def test_build_client_no_tls_by_default():
    settings = Settings(mqtt_tls=False)
    client = build_client(settings)
    assert client._ssl_context is None
