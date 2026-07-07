import os
import importlib


def _fresh_settings(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    from app import config as config_module
    importlib.reload(config_module)
    return config_module.Settings()


def test_defaults_match_insecure_profile(monkeypatch):
    monkeypatch.delenv("DEVICE_ID", raising=False)
    settings = _fresh_settings(monkeypatch)
    assert settings.device_id == "device-insecure"
    assert settings.admin_user == "admin"
    assert settings.admin_pass == "admin"
    assert settings.expose_api_key is True


def test_env_overrides_are_respected(monkeypatch):
    settings = _fresh_settings(
        monkeypatch,
        DEVICE_ID="device-hardened",
        ADMIN_PASS="Str0ng-Uniqu3-P@ss",
        EXPOSE_API_KEY="false",
        MQTT_TLS="true",
    )
    assert settings.device_id == "device-hardened"
    assert settings.admin_pass == "Str0ng-Uniqu3-P@ss"
    assert settings.expose_api_key is False
    assert settings.mqtt_tls is True
