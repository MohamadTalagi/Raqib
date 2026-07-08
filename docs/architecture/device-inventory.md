# Device Inventory

| device_id | vendor | model | mac | firmware | transport | mqtt target |
|---|---|---|---|---|---|---|
| device-insecure | AcmeCam | AC-100 | AA:BB:CC:00:11:22 | 1.0.0-old | HTTP | mqtt-broker-insecure (plaintext) |
| device-partial | AcmeCam | AC-200 | AA:BB:CC:00:11:33 | 1.5.0-mid | HTTPS (weak cert) | mqtt-broker-insecure (plaintext) |
| device-hardened | AcmeCam | AC-300 | AA:BB:CC:00:11:44 | 2.0.0-current | HTTPS (strong cert) | mqtt-broker-secure (TLS) |

Source of truth: `lab/devices/smart-camera/profiles/{insecure,partial,hardened}.env`.
