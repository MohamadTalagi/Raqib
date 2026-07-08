# Phases 0-5 Acceptance Verification

## Day 1

- [x] Working compose env (`lab/docker-compose.yml`, 6 services + cert-init, 2 networks)
- [x] ≥1 device (3: device-insecure, device-partial, device-hardened)
- [x] ≥3 exposed services inside the lab (HTTP/HTTPS x3, Telnet, MQTT x2 = 6)
- [x] Network diagram (`docs/architecture/architecture-diagram.md`)
- [x] Threat model (`docs/architecture/threat-model-stride.md`)
- [x] Device inventory (`docs/architecture/device-inventory.md`)
- [x] README (`lab/README.md`)
- [x] Demonstrated: reach device web UI, connect to MQTT, detect ≥3 open ports, view metadata — all
      from inside the lab network (Task 11, Step 4)

## Day 2

- [x] ≥8 manual findings (12 evidence entries collected across all required categories)
- [x] Each finding: raw output → structured evidence (schema-validated) → interpretation (`finding`
      field) → remediation (carried by the matching control in Day 3)
- [x] Evidence summary (`docs/architecture/evidence-summary.md`)

Evidence entries include:
- TEST-NET-PORTSCAN x2 (Tasks 26.1-26.2: nmap detection across device-insecure, device-partial)
- TEST-AUTH-DEFAULT-CREDS x2 (Tasks 26.3-26.4: default credentials on insecure and partial devices)
- TEST-ADMIN-UNAUTH x1 (Task 26.5: admin endpoint without authentication on insecure)
- TEST-HTTP-HEADERS x1 (Task 26.6: security headers analysis)
- TEST-TLS-CONFIG x2 (Tasks 26.7-26.8: weak cert on partial, strong cert on hardened)
- TEST-MQTT-OPEN x2 (Tasks 26.9-26.10: unencrypted MQTT on insecure/partial, encrypted on hardened)
- TEST-FW-SECRETS x1 (Task 26.11: hard-coded secrets in firmware archive)
- TEST-FW-SBOM x1 (Task 26.12: SBOM via Syft)

All evidence schema-valid: validated via `policies.schema.validate.validate_evidence()`.

## Day 3

- [x] First 5 controls mapped to Saudi CGIoT-1:2024 sources (`policies/controls/SA-IOT-001..005.yaml`)
  - SA-IOT-001: Device Identification (CGIoT-1:2024 §3.1.1)
  - SA-IOT-002: Default Credentials (CGIoT-1:2024 §3.2.1)
  - SA-IOT-003: Unnecessary Services (CGIoT-1:2024 §3.1.3)
  - SA-IOT-004: Secure Communications (CGIoT-1:2024 §3.3.1)
  - SA-IOT-005: TLS Configuration (CGIoT-1:2024 §3.3.2)

- [x] Minimal policy engine: load control → read evidence → apply verdict logic → output verdict
      JSON (`policies/engine/policy_engine.py` + `generate_verdicts.py`)

- [x] ≥2 controls produce correct Pass and Fail verdicts across different device configs
  - SA-IOT-002 (Default Credentials): PASS on device-hardened, FAIL on device-insecure
  - SA-IOT-003 (Unnecessary Services): PASS on device-hardened, FAIL on device-insecure
  - SA-IOT-004 (Secure Communications): PASS on device-hardened, FAIL on device-insecure
  - SA-IOT-005 (TLS Configuration): PASS on device-hardened, FAIL on device-partial

  Total: 4 controls with both correct PASS and FAIL verdicts, far exceeding the required ≥2.

## Determinism Check

- [x] No `eval`/`exec` anywhere in `policies/engine/policy_engine.py`
  - Verified by: `grep -n "eval(\|exec(" policies/engine/policy_engine.py`
  - Result: `clean: no eval/exec found`

## Test Suite

All tests pass across the entire Phase 0-5 codebase:

- **policies/engine/** (2 tests + 1 generate_verdicts test = 3 tests)
  - `test_policy_engine.py`: 7 tests (field resolution, condition matching, Saudi source formatting, inconclusive handling)
  - `test_generate_verdicts.py`: 1 test (verdicts produce FAIL and PASS across devices)

- **policies/schema/** (8 tests)
  - `test_validate.py`: Evidence validation (valid/invalid evidence, confidence enum, SHA256 format), Verdict validation, Control validation

- **lab/auditor/worker/tests/** (3 tests)
  - `test_record_evidence.py`: Evidence JSON writing, raw output copying, sequence incrementing

- **lab/devices/smart-camera/tests/** (17 tests)
  - `test_config.py`: 2 tests (profile defaults, env overrides)
  - `test_main.py`: 12 tests (login, endpoints, config exposure, firmware, admin, privacy, health)
  - `test_mqtt_publisher.py`: 3 tests (client_id, TLS, no-TLS)

**Total: 36 tests passed** (policies: 16, auditor: 3, smart-camera: 17)

All tests executed successfully with no failures.
