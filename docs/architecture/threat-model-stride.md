# STRIDE Threat Model — Smart Camera Devices

| STRIDE | Threat (against the device) | Demonstrated by | Mitigation on device-hardened |
|---|---|---|---|
| Spoofing | Anonymous MQTT publish; admin/admin login | `mqtt-broker-insecure` (allow_anonymous true), device-insecure default creds | `mqtt-broker-secure` requires TLS + password auth; unique strong admin credential |
| Tampering | Plaintext MITM on HTTP/MQTT; unsigned firmware accepted by update.sh | device-insecure HTTP transport, insecure firmware's `update.sh` (no checksum) | HTTPS-only strong TLS; `update.sh` verifies an OpenSSL signature before applying |
| Repudiation | Missing/weak logging of admin actions | device-insecure `LOGGING_MODE=off` | device-hardened `LOGGING_MODE=security` |
| Information Disclosure | Hard-coded API key/private key; `/api/config` leak; Telnet plaintext banner | `TEST-FW-SECRETS` YARA findings, device-insecure `/api/config` response, telnet-sim banner | No secrets baked into hardened firmware; API key never exposed (`EXPOSE_API_KEY=false`); Telnet removed entirely |
| Denial of Service | Unnecessary open services (Telnet) increase attack surface | `telnet-sim` reachable from device-insecure's network segment | Telnet container simply isn't part of the hardened device's exposed surface (services minimized) |
| Elevation of Privilege | Unauthenticated admin endpoint | `TEST-ADMIN-UNAUTH` — device-insecure's `/api/admin/reset` requires no auth | device-hardened sets `REQUIRE_ADMIN_AUTH=true`, enforced in `app/main.py`'s `admin_reset()` |

The platform's own defense against a compromised device is the trust-boundary design in
`trust-boundary-diagram.md`: even a fully compromised `device-insecure` cannot reach
`internal-network` or write to `document-store` directly — only `auditor-worker` can.
