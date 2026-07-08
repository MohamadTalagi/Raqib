import json
import threading
import time

import paho.mqtt.client as mqtt

from app.config import Settings, settings as default_settings


def build_client(settings: Settings) -> mqtt.Client:
    client = mqtt.Client(client_id=settings.device_id)
    if settings.mqtt_tls:
        client.tls_set(ca_certs=settings.mqtt_ca_cert or None)
    return client


def _publish_loop(settings: Settings) -> None:
    client = build_client(settings)
    while True:
        try:
            client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=30)
            client.loop_start()
            break
        except OSError:
            time.sleep(2)

    topic = f"devices/{settings.device_id}/telemetry"
    while True:
        payload = json.dumps({"device_id": settings.device_id, "status": "ok", "ts": time.time()})
        client.publish(topic, payload)
        time.sleep(10)


def start_mqtt_publisher(settings: Settings = default_settings) -> None:
    thread = threading.Thread(target=_publish_loop, args=(settings,), daemon=True)
    thread.start()
