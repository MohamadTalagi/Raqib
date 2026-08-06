"""Seeds the six pre-existing lab devices into the devices tables.

Idempotent: safe to run repeatedly, because it will be - once against the
local dev database and once against the PC's real one (init.sql does not
re-run on an initialized volume; see docs/errors/021).

device_id values here are load-bearing: committed Day-2 evidence references
them byte-for-byte. This module only ever INSERTs into devices and
device_services - it never touches evidence or verdicts.

Tiers for the first five are lifted verbatim from the frontend's former
deviceMeta.ts. telnet-sim's metadata is newly authored: it never had a device
card, but it is a real nmap scan target.

The three camera profiles' display names and descriptions were originally
posture labels ("Smart Camera - Insecure", "Default creds, plain HTTP,
Telnet, ..."). They are now the real vendor/model each fixture actually
reports over the wire, with neutral product descriptions, so an assessment
has to DISCOVER a device's posture from evidence rather than read it off the
inventory label - which is the whole point of the exercise, and closer to a
real engagement where nothing is pre-labelled "insecure".

The posture itself is not hidden anywhere it matters: `tier` below is
unchanged, the device_ids are unchanged (they are load-bearing - committed
Day-2 evidence, verdicts and raw output files all join on those exact
strings, and they are the Docker service names), and every scan still reports
what it really finds.
"""

SEED_DEVICES = [
    {
        "device_id": "device-insecure",
        "display_name": "Hikvision DS-2CD2143G2-I",
        "description": "4 MP fixed dome network camera. Web management interface, MQTT telemetry.",
        "tier": "insecure",
        "host": "device-insecure",
        "services": [
            {"service_type": "http", "port": 80, "published_port": 8081},
            {"service_type": "telnet", "port": 23, "published_port": None},
        ],
    },
    {
        "device_id": "device-partial",
        "display_name": "Hikvision DS-2CD2143G2-IU",
        "description": "4 MP fixed dome network camera with built-in microphone. Web management interface, MQTT telemetry.",
        "tier": "partial",
        "host": "device-partial",
        "services": [{"service_type": "https", "port": 443, "published_port": 8082}],
    },
    {
        "device_id": "device-hardened",
        "display_name": "Axis M3216-LVE",
        "description": "4 MP outdoor-ready fixed dome network camera. Web management interface, MQTT telemetry.",
        "tier": "hardened",
        "host": "device-hardened",
        "services": [{"service_type": "https", "port": 443, "published_port": 8083}],
    },
    {
        "device_id": "mqtt-broker-insecure",
        "display_name": "MQTT Broker — Insecure",
        "description": "Unauthenticated, plaintext MQTT on port 1883.",
        "tier": "insecure",
        "host": "mqtt-broker-insecure",
        "services": [{"service_type": "mqtt", "port": 1883, "published_port": 18830}],
    },
    {
        "device_id": "mqtt-broker-secure",
        "display_name": "MQTT Broker — Secure",
        "description": "TLS-only MQTT on port 8883 with certificate auth.",
        "tier": "hardened",
        "host": "mqtt-broker-secure",
        "services": [{"service_type": "mqtts", "port": 8883, "published_port": None}],
    },
    {
        "device_id": "telnet-sim",
        "display_name": "Telnet Service Simulator",
        "description": "Standalone legacy Telnet service on port 23, used as an insecure-protocol scan target.",
        "tier": "insecure",
        "host": "telnet-sim",
        "services": [{"service_type": "telnet", "port": 23, "published_port": None}],
    },
]


def seed(conn) -> int:
    """Insert any missing seed devices and repair any missing service rows.

    Returns how many *devices* were newly inserted (not how many service rows
    were touched) - a second run against a fully-seeded database returns 0
    even though the service inserts below still ran, because they are all
    ON CONFLICT DO NOTHING no-ops at that point. Service inserts always run,
    independent of whether the device row was already present, so this can
    repair a database where a device row survived but its device_services
    rows were lost - that used to be unreachable because the service inserts
    were nested inside the "device was newly inserted" branch.
    """
    inserted = 0
    for device in SEED_DEVICES:
        result = conn.execute(
            """
            INSERT INTO devices (device_id, display_name, description, tier, host, source)
            VALUES (%s, %s, %s, %s, %s, 'seeded')
            ON CONFLICT (device_id) DO NOTHING
            """,
            (
                device["device_id"], device["display_name"], device["description"],
                device["tier"], device["host"],
            ),
        )
        if result.rowcount != 0:
            inserted += 1
        for service in device["services"]:
            conn.execute(
                """
                INSERT INTO device_services (device_id, service_type, port, published_port)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (device_id, service_type, port) DO NOTHING
                """,
                (
                    device["device_id"], service["service_type"],
                    service["port"], service["published_port"],
                ),
            )
    conn.commit()
    return inserted


if __name__ == "__main__":
    import os

    import psycopg

    url = os.environ["DATABASE_URL"]
    connection = psycopg.connect(url)
    try:
        print(f"Seeded {seed(connection)} devices")
    finally:
        connection.close()
