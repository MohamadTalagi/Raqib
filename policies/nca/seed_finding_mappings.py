"""Seeds compliance_finding_mappings - the configurable table that links a
scan_tests.py observation shape to the NCA control(s) it's relevant evidence
for. Edit this list and re-run to change the mapping; there is deliberately
no mapping logic hardcoded anywhere else (see finding_mappings.py's
docstring). Every match_rule field name here is a real key one of
policies/catalog/scan_tests.py's `_parse_*_observations` functions actually
returns - none are invented.

Idempotent via the table's UNIQUE(finding_key, control_id). Requires
compliance_controls to already be seeded (see seed_catalog.py) since
control_id is a foreign key.

Each mapping carries a `verdict_hint` (default "fail"): every rule below
fires precisely when an insecure condition is present, so a match suggests
a FAIL. The handful that only surface "relevant evidence for a manual
review" (update script / component manifest present, Server banner
discloses a framework) are marked "review_required" instead - they cannot
imply a pass or a fail on their own. The per-device assessment workspace
reads this to pre-fill a suggested status the auditor still confirms.

Deliberately absent: any mapping into domain 1 (governance), or the
supplier/cloud guideline groups - those describe policy approval, personnel
training, audits, and supplier/cloud contracts, none of which a network or
device scan can demonstrate. They stay manual-assessment-only.
"""

import json

from policies.nca.build_catalog import control_id

MAPPINGS = [
    {
        "finding_key": "default-creds-accepted",
        "description": "A default/well-known credential pair was accepted on login.",
        "control_id": control_id("2-2-2"),
        "match_rule": {"field": "observations.default_creds", "op": "equals", "value": True},
        "manufacturer_principle": "Manufacturer Principle 5",
    },
    {
        "finding_key": "firmware-hardcoded-secret",
        "description": "A hard-coded password pattern was found inside the firmware archive.",
        "control_id": control_id("2-2-2"),
        "match_rule": {"field": "observations.hardcoded_secret_found", "op": "equals", "value": True},
        "manufacturer_principle": "Manufacturer Principle 5",
    },
    {
        "finding_key": "dashboard-reachable-without-session",
        "description": "An authenticated page was reachable with no session state carried over from login.",
        "control_id": control_id("2-2-1"),
        "match_rule": {"field": "observations.dashboard_accessible_without_session", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "no-session-cookie-issued",
        "description": "Login did not issue a session cookie, so no session boundary is enforced.",
        "control_id": control_id("2-2-1"),
        "match_rule": {"field": "observations.session_cookie_issued", "op": "equals", "value": False},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "anonymous-config-access",
        "description": "The device configuration endpoint returned data with no credentials supplied.",
        "control_id": control_id("2-2-1"),
        "match_rule": {"field": "observations.anonymous_access_allowed", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "api-key-exposed-anonymously",
        "description": "A live API key was present in an unauthenticated response.",
        "control_id": control_id("2-2-2"),
        "match_rule": {"field": "observations.api_key_exposed", "op": "equals", "value": True},
        "manufacturer_principle": "Manufacturer Principle 5",
    },
    {
        "finding_key": "admin-endpoint-unauthenticated",
        "description": "An administrative action executed with no Authorization header.",
        "control_id": control_id("2-14-1"),
        "match_rule": {"field": "observations.admin_unauthenticated", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "unnecessary-service-telnet-open",
        "description": "Telnet (port 23) was found open during a full port-range scan.",
        "control_id": control_id("2-15-2"),
        "match_rule": {"field": "observations.open_ports", "op": "contains", "value": 23},
        "manufacturer_principle": "Manufacturer Principle 3",
    },
    {
        "finding_key": "mqtt-anonymous-access",
        "description": "The MQTT broker accepted a subscription with no credentials.",
        "control_id": control_id("2-4-2"),
        "match_rule": {"field": "observations.mqtt_anonymous", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "mqtt-unencrypted-transport-transactions",
        "description": "MQTT traffic is unencrypted, so payloads and any credentials are visible on the wire.",
        "control_id": control_id("2-4-3"),
        "match_rule": {"field": "observations.mqtt_tls", "op": "equals", "value": False},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "mqtt-unencrypted-transport-comms",
        "description": "MQTT traffic is unencrypted, so payloads and any credentials are visible on the wire.",
        "control_id": control_id("2-7-2"),
        "match_rule": {"field": "observations.mqtt_tls", "op": "equals", "value": False},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "plaintext-traffic-captured-transactions",
        "description": "A request/response was visible in cleartext in a packet capture.",
        "control_id": control_id("2-4-3"),
        "match_rule": {"field": "observations.plaintext_get_visible", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "plaintext-traffic-captured-comms",
        "description": "A request/response was visible in cleartext in a packet capture.",
        "control_id": control_id("2-7-2"),
        "match_rule": {"field": "observations.plaintext_get_visible", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "tls-weak-cipher",
        "description": "The TLS certificate's key is below the minimum accepted strength.",
        "control_id": control_id("2-4-3"),
        "match_rule": {"field": "observations.weak_cipher", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "tls-deprecated-protocol-version",
        "description": "The negotiated TLS/SSL protocol version is deprecated.",
        "control_id": control_id("2-4-3"),
        "match_rule": {
            "field": "observations.tls_version",
            "op": "in",
            "value": ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"],
        },
        "manufacturer_principle": None,
    },
    {
        "finding_key": "firmware-update-script-present",
        "description": "An update script was found in the firmware archive - relevant evidence for confirming signed/verified updates.",
        "control_id": control_id("2-4-6"),
        "match_rule": {"field": "observations.update_script_present", "op": "equals", "value": True},
        "manufacturer_principle": None,
        "verdict_hint": "review_required",
    },
    {
        "finding_key": "firmware-manifest-present",
        "description": "A component manifest was found in the firmware archive - relevant evidence for a manual CVE/obsolescence review.",
        "control_id": control_id("2-9-1"),
        "match_rule": {"field": "observations.manifest_present", "op": "equals", "value": True},
        "manufacturer_principle": None,
        "verdict_hint": "review_required",
    },
    {
        "finding_key": "http-banner-discloses-framework",
        "description": "The Server header discloses the underlying framework - relevant evidence for a manual CVE/obsolescence review.",
        "control_id": control_id("2-9-1"),
        "match_rule": {"field": "observations.banner_discloses_framework", "op": "equals", "value": True},
        "manufacturer_principle": None,
        "verdict_hint": "review_required",
    },
    {
        "finding_key": "firmware-cert-or-key-embedded",
        "description": "A private key or certificate shared across every unit of this firmware image was found in the archive.",
        "control_id": control_id("2-15-1"),
        "match_rule": {"field": "observations.cert_or_key_present", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "missing-security-headers",
        "description": "One or more browser-enforced security headers are missing from the web interface.",
        "control_id": control_id("2-14-1"),
        "match_rule": {"field": "observations.missing_security_headers", "op": "not_equals", "value": []},
        "manufacturer_principle": None,
    },
    # The 5 device-variety fixtures added below (smart lock, industrial
    # sensor gateway, router/gateway, NVR, smart speaker) are the first
    # device-scope evidence ever mapped into 2-13 (Physical Security) and 2-6
    # (Data and Information Protection) - every mapping above only ever
    # touches 2-2/2-4/2-7/2-9/2-14/2-15, so those two subdomains previously
    # had zero device-scope finding mappings despite being real, already
    # -seeded CGIoT-1:2024 controls.
    {
        "finding_key": "physical-tamper-detection-not-wired",
        "description": "The device reports no hardware tamper-detection mechanism wired up.",
        "control_id": control_id("2-13-2"),
        "match_rule": {"field": "observations.tamper_detection_wired", "op": "equals", "value": False},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "modbus-unauthenticated-protocol",
        "description": "Modbus TCP answered an unauthenticated discovery probe - the protocol has no native authentication.",
        "control_id": control_id("2-15-2"),
        "match_rule": {"field": "observations.modbus_port_open", "op": "equals", "value": True},
        "manufacturer_principle": "Manufacturer Principle 3",
    },
    {
        "finding_key": "modbus-unencrypted-protocol",
        "description": "Modbus TCP traffic is unencrypted, so register/coil reads and writes are visible and forgeable on the wire.",
        "control_id": control_id("2-4-3"),
        "match_rule": {"field": "observations.modbus_port_open", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "upnp-unauthenticated-discovery",
        "description": "The device answered an unauthenticated SSDP/UPnP discovery query and accepts port-forward requests the same way.",
        "control_id": control_id("2-4-3"),
        "match_rule": {"field": "observations.upnp_reachable", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "rtsp-unauthenticated-stream-protection",
        "description": "The RTSP video stream can be accessed with no authentication, exposing recorded/live footage to any network-adjacent client.",
        "control_id": control_id("2-6-2"),
        "match_rule": {"field": "observations.unauthenticated_stream_access", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "rtsp-unauthenticated-stream-minimization",
        "description": "The RTSP video stream can be accessed with no authentication, exposing recorded/live footage to any network-adjacent client.",
        "control_id": control_id("2-6-3"),
        "match_rule": {"field": "observations.unauthenticated_stream_access", "op": "equals", "value": True},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "mdns-voice-log-unencrypted-protection",
        "description": "The device broadcasts over mDNS that its voice-command log is not encrypted at rest.",
        "control_id": control_id("2-6-2"),
        "match_rule": {
            "field": "observations.txt_record.txt.voice_log_encrypted",
            "op": "equals",
            "value": "false",
        },
        "manufacturer_principle": None,
    },
    {
        "finding_key": "mdns-voice-log-unencrypted-minimization",
        "description": "The device broadcasts over mDNS that its voice-command log is not encrypted at rest.",
        "control_id": control_id("2-6-3"),
        "match_rule": {
            "field": "observations.txt_record.txt.voice_log_encrypted",
            "op": "equals",
            "value": "false",
        },
        "manufacturer_principle": None,
    },
    # The 3 mappings below back the Phase 4 device-scope collectors added
    # for peer authentication (2-4-5) and event logging/monitoring (2-11-1,
    # 2-11-2) - each raised that guideline's assessment_type from "manual"
    # to "hybrid" in build_catalog.py, since the signal is real but only
    # ever a heuristic (a conventional-path check, not exhaustive proof).
    {
        "finding_key": "tls-no-client-certificate-required",
        "description": "The TLS handshake never requests a client certificate - any TLS client can connect with no cryptographic peer authentication.",
        "control_id": control_id("2-4-5"),
        "match_rule": {"field": "observations.client_cert_requested", "op": "equals", "value": False},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "no-security-log-endpoint",
        "description": "No conventional security/access-log endpoint was found on this device.",
        "control_id": control_id("2-11-1"),
        "match_rule": {"field": "observations.security_log_endpoint_present", "op": "equals", "value": False},
        "manufacturer_principle": None,
    },
    {
        "finding_key": "no-diagnostic-monitoring-endpoint",
        "description": "No conventional diagnostic/monitoring endpoint was found on this device.",
        "control_id": control_id("2-11-2"),
        "match_rule": {"field": "observations.monitoring_endpoint_present", "op": "equals", "value": False},
        "manufacturer_principle": None,
    },
]


def seed(conn) -> int:
    inserted = 0
    for mapping in MAPPINGS:
        result = conn.execute(
            """
            INSERT INTO compliance_finding_mappings (
                finding_key, description, control_id, match_rule, manufacturer_principle,
                verdict_hint
            )
            VALUES (%(finding_key)s, %(description)s, %(control_id)s, %(match_rule)s,
                    %(manufacturer_principle)s, %(verdict_hint)s)
            ON CONFLICT (finding_key, control_id) DO NOTHING
            """,
            {
                **mapping,
                "match_rule": json.dumps(mapping["match_rule"]),
                "verdict_hint": mapping.get("verdict_hint", "fail"),
            },
        )
        if result.rowcount != 0:
            inserted += 1
    conn.commit()
    return inserted


if __name__ == "__main__":
    import os

    import psycopg

    url = os.environ["DATABASE_URL"]
    connection = psycopg.connect(url)
    try:
        print(f"Inserted {seed(connection)} finding mappings")
    finally:
        connection.close()
