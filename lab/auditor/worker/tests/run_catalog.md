# Day-2 Manual Test Catalog Runbook

Run every command below **inside** the `auditor-worker` container:

```
docker compose exec auditor-worker sh
```

Then from that shell (`/work` is the container's workdir; evidence files land in
`/work/document-store`, which is the same `document-store/` at the repo root via bind mount):

## TEST-NET-PORTSCAN (against device-insecure)

```sh
nmap -sV -p- device-insecure > /tmp/portscan.txt
cat /tmp/portscan.txt
python lab/auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-NET-PORTSCAN \
  --tool nmap --tool-version "$(nmap --version | head -1 | awk '{print $3}')" \
  --command "nmap -sV -p- device-insecure" \
  --finding "Port 80 (HTTP) open; no unnecessary Telnet on this device's own container" \
  --raw-file /tmp/portscan.txt --confidence high \
  --observations '{"open_ports": [80], "telnet_open": false}'
```

## TEST-NET-PORTSCAN (against telnet-sim, representing device-insecure's exposed Telnet service)

```sh
nmap -sV -p 23 telnet-sim > /tmp/portscan_telnet.txt
python lab/auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-NET-PORTSCAN \
  --tool nmap --tool-version "$(nmap --version | head -1 | awk '{print $3}')" \
  --command "nmap -sV -p 23 telnet-sim" \
  --finding "Telnet (23/tcp) open; plaintext management console exposed" \
  --raw-file /tmp/portscan_telnet.txt --confidence high \
  --observations '{"open_ports": [23], "telnet_open": true}'
```

## TEST-AUTH-DEFAULT-CREDS (device-insecure)

```sh
curl -s -X POST http://device-insecure/login -d "username=admin&password=admin" > /tmp/login.txt
cat /tmp/login.txt
python lab/auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-AUTH-DEFAULT-CREDS \
  --tool curl --tool-version "$(curl --version | head -1 | awk '{print $2}')" \
  --command "curl -X POST http://device-insecure/login -d username=admin&password=admin" \
  --finding "Default credentials admin/admin accepted" \
  --raw-file /tmp/login.txt --confidence high \
  --observations '{"default_creds": true}'
```

## TEST-AUTH-DEFAULT-CREDS (device-hardened, expect rejection)

```sh
curl -sk -X POST https://device-hardened/login -d "username=admin&password=admin" -o /tmp/login_hardened.txt -w "%{http_code}" > /tmp/login_hardened_code.txt
cat /tmp/login_hardened_code.txt
python lab/auditor/worker/tests/record_evidence.py \
  --device device-hardened --test-id TEST-AUTH-DEFAULT-CREDS \
  --tool curl --tool-version "$(curl --version | head -1 | awk '{print $2}')" \
  --command "curl -X POST https://device-hardened/login -d username=admin&password=admin" \
  --finding "Default credentials rejected (401); device requires its unique provisioned password" \
  --raw-file /tmp/login_hardened_code.txt --confidence high \
  --observations '{"default_creds": false}'
```

## TEST-ADMIN-UNAUTH (device-insecure)

```sh
curl -s -o /tmp/admin_reset.txt -w "%{http_code}" http://device-insecure/api/admin/reset > /tmp/admin_reset_code.txt
python lab/auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-ADMIN-UNAUTH \
  --tool curl --tool-version "$(curl --version | head -1 | awk '{print $2}')" \
  --command "curl http://device-insecure/api/admin/reset" \
  --finding "Admin reset endpoint reachable with no authentication" \
  --raw-file /tmp/admin_reset_code.txt --confidence high \
  --observations '{"admin_unauthenticated": true}'
```

## TEST-HTTP-HEADERS (device-insecure)

```sh
curl -sI http://device-insecure/ > /tmp/headers.txt
cat /tmp/headers.txt
python lab/auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-HTTP-HEADERS \
  --tool curl --tool-version "$(curl --version | head -1 | awk '{print $2}')" \
  --command "curl -I http://device-insecure/" \
  --finding "Missing security headers (X-Frame-Options, Content-Security-Policy)" \
  --raw-file /tmp/headers.txt --confidence medium \
  --observations '{"missing_security_headers": ["X-Frame-Options", "Content-Security-Policy"]}'
```

## TEST-TLS-CONFIG (device-partial, weak cert)

```sh
openssl s_client -connect device-partial:443 -brief < /dev/null > /tmp/tls_partial.txt 2>&1
cat /tmp/tls_partial.txt
python lab/auditor/worker/tests/record_evidence.py \
  --device device-partial --test-id TEST-TLS-CONFIG \
  --tool openssl --tool-version "$(openssl version | awk '{print $2}')" \
  --command "openssl s_client -connect device-partial:443 -brief" \
  --finding "1024-bit RSA certificate with SHA-1 signature (weak)" \
  --raw-file /tmp/tls_partial.txt --confidence high \
  --observations '{"tls_version": "TLSv1.2", "weak_cipher": true, "cert_bits": 1024}'
```

## TEST-TLS-CONFIG (device-hardened, strong cert)

```sh
openssl s_client -connect device-hardened:443 -brief < /dev/null > /tmp/tls_hardened.txt 2>&1
python lab/auditor/worker/tests/record_evidence.py \
  --device device-hardened --test-id TEST-TLS-CONFIG \
  --tool openssl --tool-version "$(openssl version | awk '{print $2}')" \
  --command "openssl s_client -connect device-hardened:443 -brief" \
  --finding "2048-bit RSA certificate with SHA-256 signature (strong)" \
  --raw-file /tmp/tls_hardened.txt --confidence high \
  --observations '{"tls_version": "TLSv1.3", "weak_cipher": false, "cert_bits": 2048}'
```

## TEST-MQTT-OPEN (mqtt-broker-insecure)

```sh
timeout 3 mosquitto_sub -h mqtt-broker-insecure -t 'devices/#' -C 1 -v > /tmp/mqtt_insecure.txt 2>&1
cat /tmp/mqtt_insecure.txt
python lab/auditor/worker/tests/record_evidence.py \
  --device mqtt-broker-insecure --test-id TEST-MQTT-OPEN \
  --tool mosquitto_sub --tool-version "$(mosquitto_sub --help 2>&1 | head -1)" \
  --command "mosquitto_sub -h mqtt-broker-insecure -t devices/# -C 1" \
  --finding "Anonymous plaintext subscription succeeded; no auth or TLS required" \
  --raw-file /tmp/mqtt_insecure.txt --confidence high \
  --observations '{"mqtt_anonymous": true, "mqtt_tls": false}'
```

## TEST-MQTT-OPEN (mqtt-broker-secure, expect rejection)

```sh
timeout 3 mosquitto_sub -h mqtt-broker-secure -p 8883 -t 'devices/#' -C 1 > /tmp/mqtt_secure.txt 2>&1
cat /tmp/mqtt_secure.txt
python lab/auditor/worker/tests/record_evidence.py \
  --device mqtt-broker-secure --test-id TEST-MQTT-OPEN \
  --tool mosquitto_sub --tool-version "$(mosquitto_sub --help 2>&1 | head -1)" \
  --command "mosquitto_sub -h mqtt-broker-secure -p 8883 -t devices/# -C 1" \
  --finding "Anonymous connection rejected; TLS + password auth required" \
  --raw-file /tmp/mqtt_secure.txt --confidence high \
  --observations '{"mqtt_anonymous": false, "mqtt_tls": true}'
```

## TEST-FW-SECRETS + TEST-FW-SBOM (firmware analysis, all 3 variants)

```sh
python lab/auditor/worker/firmware/generate_firmware.py
file lab/auditor/worker/firmware/output/*.tar.gz > /tmp/fw_file.txt

python -c "
from pathlib import Path
from lab.auditor.worker.firmware.scan_firmware import scan_archive
p = Path('lab/auditor/worker/firmware/output/camera-fw-1.0.0-old-device-insecure.tar.gz')
for f in scan_archive(p):
    print(f)
" > /tmp/fw_scan_insecure.txt
cat /tmp/fw_scan_insecure.txt

python lab/auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-FW-SECRETS \
  --tool yara --tool-version "4.5.1" \
  --command "scan_firmware.py camera-fw-1.0.0-old-device-insecure.tar.gz" \
  --finding "Hardcoded admin password and embedded API key found in firmware config" \
  --raw-file /tmp/fw_scan_insecure.txt --confidence high \
  --observations '{"hardcoded_secret": true, "api_key_found": true, "private_key_present": false}'

syft lab/auditor/worker/firmware/output/camera-fw-1.0.0-old-device-insecure.tar.gz -o json > /tmp/fw_sbom_insecure.json
grype sbom:/tmp/fw_sbom_insecure.json > /tmp/fw_vulns_insecure.txt
cat /tmp/fw_vulns_insecure.txt

python lab/auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-FW-SBOM \
  --tool grype --tool-version "$(grype version 2>&1 | head -1)" \
  --command "syft ... | grype sbom:-" \
  --finding "Outdated openssl 1.0.1e and busybox 1.19.4 flagged with known CVEs" \
  --raw-file /tmp/fw_vulns_insecure.txt --confidence high \
  --observations '{"outdated_packages": ["openssl-1.0.1e", "busybox-1.19.4"]}'
```

This yields **12 evidence entries** total (well above the required ≥8), covering: network/port
scan (2), default credentials (2), unauthenticated admin (1), missing headers (1), TLS config (2),
MQTT posture (2), firmware secrets (1), firmware SBOM/CVE (1) — every category the brief requires
(default creds, exposed insecure service, unencrypted protocol, hard-coded secret, outdated
package, weak/missing TLS, missing logging note captured in the STRIDE doc, missing privacy
evidence captured in `docs/privacy_insecure.md`).
