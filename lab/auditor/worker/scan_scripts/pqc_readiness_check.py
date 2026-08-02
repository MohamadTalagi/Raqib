"""Compound helper for TEST-PQC-TLS-HANDSHAKE (Post-Quantum Readiness bonus
stage, informational only - never touches policies/risk/risk_engine.py):
does this device negotiate a hybrid post-quantum TLS key-exchange group,
and is its certificate signed with a post-quantum signature algorithm?

Two separate handshakes, same reason tls_cert_check.py needs two: the
negotiated-group line comes from a plain `s_client` handshake offering PQC
groups; the certificate's own signature algorithm needs its PEM
(`-showcerts` - confirmed live, same as tls_cert_check.py, that `-brief`
suppresses the PEM even together with `-showcerts`) fed into a second
`openssl x509 -noout -text` call, not expressible as one argv command
without a shell pipe, which this project never uses.

Confirmed live against this project's own auditor-worker image (OpenSSL
3.5.6) before writing this: `openssl list -kem-algorithms` shows native
ML-KEM-512/768/1024 (NIST FIPS 203) support, and `-groups` accepts the 4
hybrid names below directly. Real device-hardened/device-partial/
mqtt-broker-secure handshakes in this lab all negotiated X25519MLKEM768
when this was checked - not assumed.
"""

import re
import subprocess
import sys

HANDSHAKE_TIMEOUT_S = 10
X509_TIMEOUT_S = 5

CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

# Hybrid PQC groups offered first (so a PQC-capable server negotiates one
# of these), classical groups last as a fallback so a non-PQC server still
# completes a handshake rather than failing outright. All 4 hybrid names
# and the KEM they wrap (ML-KEM, NIST FIPS 203) were confirmed live via
# `openssl list -kem-algorithms` against this project's own worker image -
# never assumed from documentation alone.
PQC_HYBRID_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "X448MLKEM1024", "SecP384r1MLKEM1024")
CLASSICAL_FALLBACK_GROUPS = ("X25519", "secp256r1", "X448", "secp384r1")
GROUPS_ARG = ":".join(PQC_HYBRID_GROUPS + CLASSICAL_FALLBACK_GROUPS)


def main() -> None:
    host, port = sys.argv[1], sys.argv[2]

    handshake = subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-groups", GROUPS_ARG, "-tls1_3"],
        capture_output=True, text=True, timeout=HANDSHAKE_TIMEOUT_S, stdin=subprocess.DEVNULL,
    )
    print(handshake.stdout)
    print(handshake.stderr)

    with_certs = subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-showcerts", "-groups", GROUPS_ARG, "-tls1_3"],
        capture_output=True, text=True, timeout=HANDSHAKE_TIMEOUT_S, stdin=subprocess.DEVNULL,
    )
    match = CERT_RE.search(with_certs.stdout + with_certs.stderr)
    if not match:
        print("cert_pem_found=False")
    else:
        print("cert_pem_found=True")
        sig = subprocess.run(
            ["openssl", "x509", "-noout", "-text"],
            input=match.group(0), capture_output=True, text=True, timeout=X509_TIMEOUT_S,
        )
        print(sig.stdout)


if __name__ == "__main__":
    main()
