from policies.nca.build_catalog import CLOUD_GUIDELINES, SUPPLIER_GUIDELINES, control_id
from policies.nca.finding_mappings import map_evidence_to_controls
from policies.nca.seed_finding_mappings import MAPPINGS


def test_every_mapping_control_id_is_a_real_guideline_reference():
    # control_id() only ever composes real guideline_ids from
    # DEVICE_TESTABLE_GUIDELINES-style strings; this just guards against a
    # typo like "2-2-20" silently seeding a dangling reference.
    for mapping in MAPPINGS:
        assert mapping["control_id"].startswith("NCA-CGIoT-1_2024-")


def test_default_creds_evidence_maps_to_2_2_2():
    evidence = {
        "test_id": "TEST-AUTH-DEFAULT-CREDS",
        "observations": {"default_creds": True, "working_credentials": [{"username": "admin", "password": "admin"}]},
    }
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-2-2") in matched


def test_no_default_creds_does_not_map_to_2_2_2_via_that_finding():
    evidence = {"test_id": "TEST-AUTH-DEFAULT-CREDS", "observations": {"default_creds": False}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-2-2") not in matched


def test_telnet_open_port_maps_to_2_15_2():
    evidence = {
        "test_id": "TEST-NET-PORTSCAN",
        "observations": {"open_ports": [23, 80], "services": []},
    }
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-15-2") in matched


def test_no_telnet_port_does_not_map_to_2_15_2():
    evidence = {"test_id": "TEST-NET-PORTSCAN", "observations": {"open_ports": [443], "services": []}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-15-2") not in matched


def test_unencrypted_mqtt_maps_to_both_2_4_3_and_2_7_2():
    evidence = {"test_id": "TEST-MQTT-OPEN", "observations": {"mqtt_tls": False, "mqtt_anonymous": True}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-4-3") in matched
    assert control_id("2-7-2") in matched
    # Same evidence also carries a separate, real signal for peer auth.
    assert control_id("2-4-2") in matched


def test_encrypted_mqtt_does_not_map_to_cleartext_controls():
    evidence = {"test_id": "TEST-MQTT-OPEN", "observations": {"mqtt_tls": True, "mqtt_anonymous": False}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-4-3") not in matched
    assert control_id("2-7-2") not in matched
    assert control_id("2-4-2") not in matched


def test_plaintext_packet_capture_maps_to_transport_controls():
    evidence = {"test_id": "TEST-NET-PKTCAPTURE", "observations": {"plaintext_get_visible": True}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-4-3") in matched
    assert control_id("2-7-2") in matched


def test_weak_tls_cipher_maps_to_2_4_3():
    evidence = {"test_id": "TEST-TLS-CONFIG", "observations": {"weak_cipher": True, "tls_version": "TLSv1.2"}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-4-3") in matched


def test_deprecated_tls_version_maps_to_2_4_3():
    evidence = {"test_id": "TEST-TLS-CONFIG", "observations": {"weak_cipher": False, "tls_version": "TLSv1.1"}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-4-3") in matched


def test_current_tls_version_and_strong_cipher_maps_to_nothing():
    evidence = {"test_id": "TEST-TLS-CONFIG", "observations": {"weak_cipher": False, "tls_version": "TLSv1.3"}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert matched == []


def test_hardcoded_firmware_secret_maps_to_2_2_2():
    evidence = {"test_id": "TEST-FW-SECRETS", "observations": {"hardcoded_secret_found": True}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-2-2") in matched


def test_missing_security_headers_maps_to_2_14_1():
    evidence = {"test_id": "TEST-HTTP-HEADERS", "observations": {"missing_security_headers": ["X-Frame-Options"]}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-14-1") in matched


def test_all_security_headers_present_maps_to_nothing_for_that_finding():
    evidence = {"test_id": "TEST-HTTP-HEADERS", "observations": {"missing_security_headers": []}}
    matched = map_evidence_to_controls(evidence, MAPPINGS)
    assert control_id("2-14-1") not in matched


def test_disabled_mapping_is_never_matched():
    evidence = {"observations": {"default_creds": True}}
    disabled = [{**MAPPINGS[0], "enabled": False}]
    assert map_evidence_to_controls(evidence, disabled) == []


def test_no_mapping_ever_targets_domain_1_governance_or_supplier_cloud_groups():
    # Organizational controls (policy, training, audits, supplier/cloud
    # contracts) must never be inferred from a scan.
    supplier_cloud_ids = {control_id(g) for g in SUPPLIER_GUIDELINES | CLOUD_GUIDELINES}
    for mapping in MAPPINGS:
        guideline_id = mapping["control_id"].removeprefix("NCA-CGIoT-1_2024-")
        assert not guideline_id.startswith("1-")
        assert mapping["control_id"] not in supplier_cloud_ids
