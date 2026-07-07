#!/bin/sh
set -e
OUT=/out
mkdir -p "$OUT"

# CA
openssl genrsa -out "$OUT/ca.key" 4096
openssl req -x509 -new -nodes -key "$OUT/ca.key" -sha256 -days 3650 \
  -subj "/CN=KAUST-IoT-Lab-CA" -out "$OUT/ca.crt"

# Weak cert for device-partial: 1024-bit RSA + SHA-1 signature (intentionally weak, lab-only)
openssl genrsa -out "$OUT/weak.key" 1024
openssl req -new -key "$OUT/weak.key" -subj "/CN=device-partial" -out "$OUT/weak.csr"
openssl x509 -req -in "$OUT/weak.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 365 -sha1 -out "$OUT/weak.crt"

# Strong cert for device-hardened: 2048-bit RSA + SHA-256
openssl genrsa -out "$OUT/strong.key" 2048
openssl req -new -key "$OUT/strong.key" -subj "/CN=device-hardened" -out "$OUT/strong.csr"
openssl x509 -req -in "$OUT/strong.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 365 -sha256 -out "$OUT/strong.crt"

# Secure MQTT broker cert: 2048-bit RSA + SHA-256
openssl genrsa -out "$OUT/mqtt-server.key" 2048
openssl req -new -key "$OUT/mqtt-server.key" -subj "/CN=mqtt-broker-secure" -out "$OUT/mqtt-server.csr"
openssl x509 -req -in "$OUT/mqtt-server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 365 -sha256 -out "$OUT/mqtt-server.crt"

rm -f "$OUT"/*.csr "$OUT"/*.srl
echo "Certificates generated in $OUT"
