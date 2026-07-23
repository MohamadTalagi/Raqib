from policies.engine.conflict import detect_conflict
from policies.engine.policy_engine import evaluate

CONTROL = {
    "control_id": "SA-IOT-004",
    "saudi_source": [{"framework": "CGIoT-1:2024", "reference": "2-4-3"}],
    "severity": "high",
    "conditions": {
        "fail": {"field": "observations.mqtt_tls", "op": "equals", "value": False},
        "partial": None,
        "pass": {"field": "observations.mqtt_tls", "op": "equals", "value": True},
        "inconclusive": {"when": "evidence_missing_or_low_confidence"},
    },
    "remediation": "Route all MQTT telemetry through the TLS-secured broker.",
}


def _row(evidence_id, mqtt_tls, source_type="automated", timestamp="2026-07-08T10:00:00Z"):
    return {
        "evidence_id": evidence_id,
        "device_id": "device-insecure",
        "timestamp": timestamp,
        "source_type": source_type,
        "observations": {"mqtt_tls": mqtt_tls},
    }


def test_single_evidence_row_is_never_a_conflict():
    row = _row("EV-1", True)
    chosen, conflict, reason = detect_conflict(CONTROL, [row])
    assert chosen is row
    assert conflict is False
    assert reason is None


def test_no_rows_returns_none_with_no_conflict():
    chosen, conflict, reason = detect_conflict(CONTROL, [])
    assert chosen is None
    assert conflict is False


def test_agreeing_evidence_rows_are_not_a_conflict():
    rows = [_row("EV-1", True, timestamp="2026-07-08T09:00:00Z"), _row("EV-2", True, timestamp="2026-07-08T10:00:00Z")]
    chosen, conflict, reason = detect_conflict(CONTROL, rows)
    assert conflict is False
    assert chosen["evidence_id"] == "EV-2"  # most recent, no disagreement to break the tie


def test_mentors_own_example_documentation_says_tls_capture_shows_plaintext():
    # "Documentation claims MQTT uses TLS. Packet capture shows plaintext MQTT."
    doc_claims_tls = _row("EV-DOC-1", mqtt_tls=True, source_type="document")
    capture_shows_plaintext = _row("EV-CAPTURE-1", mqtt_tls=False, source_type="automated")
    chosen, conflict, reason = detect_conflict(CONTROL, [doc_claims_tls, capture_shows_plaintext])
    assert conflict is True
    assert chosen["evidence_id"] == "EV-CAPTURE-1"  # directly observed technical evidence wins
    assert "EV-DOC-1" in reason
    assert "EV-CAPTURE-1" in reason


def test_manual_evidence_conflicting_with_automated_evidence_prefers_automated():
    manual = _row("EV-MANUAL", mqtt_tls=True, source_type="manual")
    automated = _row("EV-AUTO", mqtt_tls=False, source_type="automated")
    chosen, conflict, _ = detect_conflict(CONTROL, [manual, automated])
    assert conflict is True
    assert chosen["evidence_id"] == "EV-AUTO"


def test_two_conflicting_automated_rows_falls_back_to_most_recent():
    older = _row("EV-OLD", mqtt_tls=True, timestamp="2026-07-08T09:00:00Z")
    newer = _row("EV-NEW", mqtt_tls=False, timestamp="2026-07-08T11:00:00Z")
    chosen, conflict, _ = detect_conflict(CONTROL, [older, newer])
    assert conflict is True
    assert chosen["evidence_id"] == "EV-NEW"


def test_disagreement_on_an_unrelated_field_is_not_a_conflict():
    # Both rows agree on mqtt_tls (the field this control actually keys on);
    # disagreeing on some other, irrelevant field must not trigger a conflict.
    row_a = {**_row("EV-1", True), "observations": {"mqtt_tls": True, "unrelated_field": "a"}}
    row_b = {**_row("EV-2", True), "observations": {"mqtt_tls": True, "unrelated_field": "b"}}
    _, conflict, _ = detect_conflict(CONTROL, [row_a, row_b])
    assert conflict is False


def test_evaluate_records_conflict_flags_and_all_evidence_ids_when_given():
    winner = _row("EV-CAPTURE-1", mqtt_tls=False, source_type="automated")
    verdict = evaluate(
        CONTROL, winner,
        conflict_detected=True,
        conflict_reason="Conflicting evidence on observations.mqtt_tls: EV-CAPTURE-1 preferred over EV-DOC-1.",
        all_evidence_ids=["EV-DOC-1", "EV-CAPTURE-1"],
    )
    assert verdict["status"] == "FAIL"
    assert verdict["conflict_detected"] is True
    assert verdict["evidence_ids"] == ["EV-DOC-1", "EV-CAPTURE-1"]
    assert "conflicting evidence" in verdict["reason"].lower()


def test_evaluate_defaults_to_no_conflict_when_not_told_otherwise():
    verdict = evaluate(CONTROL, _row("EV-1", True))
    assert verdict["conflict_detected"] is False
    assert verdict["conflict_reason"] is None
    assert verdict["evidence_ids"] == ["EV-1"]


PORTSCAN_CONTROL = {
    "control_id": "SA-IOT-003",
    "saudi_source": [{"framework": "CGIoT-1:2024", "reference": "2-15-2"}],
    "severity": "high",
    "conditions": {
        "fail": {"field": "observations.open_ports", "op": "contains", "value": 23},
        "partial": None,
        "pass": {"field": "observations.open_ports", "op": "not_contains", "value": 23},
        "inconclusive": {"when": "evidence_missing_or_low_confidence"},
    },
    "remediation": "Remove Telnet.",
}


def test_detect_conflict_handles_unhashable_list_valued_fields():
    # Regression: observations.open_ports is a list - a plain set() of
    # values raises "unhashable type: 'list'". Must compare by equality
    # instead, not crash.
    row_a = {
        "evidence_id": "EV-1", "device_id": "device-insecure", "timestamp": "2026-07-08T09:00:00Z",
        "source_type": "automated", "observations": {"open_ports": [80]},
    }
    row_b = {
        "evidence_id": "EV-2", "device_id": "device-insecure", "timestamp": "2026-07-08T10:00:00Z",
        "source_type": "automated", "observations": {"open_ports": [23, 80]},
    }
    chosen, conflict, reason = detect_conflict(PORTSCAN_CONTROL, [row_a, row_b])
    assert conflict is True
    assert chosen["evidence_id"] == "EV-2"  # most recent, since both are automated


def test_detect_conflict_no_conflict_when_list_valued_fields_agree():
    row_a = {
        "evidence_id": "EV-1", "device_id": "device-insecure", "timestamp": "2026-07-08T09:00:00Z",
        "source_type": "automated", "observations": {"open_ports": [80]},
    }
    row_b = {
        "evidence_id": "EV-2", "device_id": "device-insecure", "timestamp": "2026-07-08T10:00:00Z",
        "source_type": "automated", "observations": {"open_ports": [80]},
    }
    _, conflict, _ = detect_conflict(PORTSCAN_CONTROL, [row_a, row_b])
    assert conflict is False
