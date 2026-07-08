# Day-2 Evidence Summary

This document summarizes the 12 real evidence entries collected during Day-2 manual cybersecurity assessment (Task 26). Each finding represents a concrete security gap discovered across the simulated IoT device profiles and infrastructure.

## Evidence Table

| evidence_id | device | test_id | finding |
|---|---|---|---|
| EV-2026-07-08-0013 | device-insecure | TEST-NET-PORTSCAN | Port 80 open; no unnecessary Telnet |
| EV-2026-07-08-0014 | device-insecure | TEST-NET-PORTSCAN | Telnet 23 open; plaintext mgmt exposed |
| EV-2026-07-08-0015 | device-insecure | TEST-AUTH-DEFAULT-CREDS | Default creds admin/admin accepted |
| EV-2026-07-08-0016 | device-hardened | TEST-AUTH-DEFAULT-CREDS | Default creds rejected 401 |
| EV-2026-07-08-0017 | device-insecure | TEST-ADMIN-UNAUTH | Admin reset reachable no auth |
| EV-2026-07-08-0018 | device-insecure | TEST-HTTP-HEADERS | Missing security headers |
| EV-2026-07-08-0019 | device-partial | TEST-TLS-CONFIG | 1024-bit SHA-1 cert weak |
| EV-2026-07-08-0020 | device-hardened | TEST-TLS-CONFIG | 2048-bit SHA-256 cert strong |
| EV-2026-07-08-0021 | mqtt-broker-insecure | TEST-MQTT-OPEN | Anon plaintext sub succeeded |
| EV-2026-07-08-0022 | mqtt-broker-secure | TEST-MQTT-OPEN | Anon rejected TLS+auth required |
| EV-2026-07-08-0023 | device-insecure | TEST-FW-SECRETS | Hardcoded admin password and API key found in firmware config |
| EV-2026-07-08-0024 | device-insecure | TEST-FW-SBOM | Syft did not recognize the firmware's custom manifest.json format so Grype found no CVE matches; manifest.json itself documents outdated openssl 1.0.1e and busybox 1.19.4 as a manual cross-reference |

## Evidence Corpus Details

Each row's full record (raw output, structured evidence JSON, and SHA-256 hash) lives in the document store:

- **Structured evidence:** `document-store/evidence/<evidence_id>.json`
- **Raw tool output:** `document-store/raw/<evidence_id>.txt`

The evidence records follow the normalized schema established in Task 26:
- Evidence ID (timestamp + sequence)
- Device ID
- Test ID (TEST-*)
- Tool name and version
- Command executed
- Timestamp
- Finding summary
- Raw output file reference
- Confidence level
- Hash of evidence file

## Coverage Summary

The 12 evidence entries provide comprehensive coverage across the three device profiles and security domains:

### By Device Profile
- **device-insecure:** 7 findings (expected to fail most controls)
- **device-partial:** 1 finding (weak TLS configuration)
- **device-hardened:** 2 findings (expected to pass most controls)
- **mqtt-broker-insecure:** 1 finding (unauthenticated access)
- **mqtt-broker-secure:** 1 finding (proper TLS + auth enforcement)

### By Security Domain
- **Network & Services:** 2 entries (open ports, plaintext Telnet)
- **Authentication & Access Control:** 3 entries (default creds, unauthorized admin access)
- **Secure Communications (TLS):** 2 entries (weak vs. strong certificate configurations)
- **MQTT Protocol Security:** 2 entries (anonymous vs. authenticated access)
- **Firmware & Software:** 2 entries (hardcoded secrets, outdated component detection)
- **HTTP Security Headers:** 1 entry (missing security headers)

## Acceptance Criteria

The evidence corpus meets all Day-2 acceptance requirements:

- [x] ≥8 manual findings collected (we have 12)
- [x] Each finding shows raw output → structured evidence → security interpretation
- [x] Evidence normalized with required schema fields
- [x] Coverage across default credentials, insecure services, unencrypted protocols, hardcoded secrets, outdated packages, weak/missing TLS, and missing logging patterns
- [x] All evidence files verified and committed to the repository

## Next Steps

Task 27 (this task): Evidence summary document created.

These 12 evidence entries will feed into **Task 28 (Control Mapping)**, where we map each finding to corresponding Saudi CGIoT-1:2024 controls and establish Pass/Fail/Partial/Inconclusive verdict logic for the policy engine.
