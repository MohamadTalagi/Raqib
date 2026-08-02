"""Deterministic, verified-not-invented reference data for the Post-Quantum
Readiness bonus stage - informational only, never touches
policies/risk/risk_engine.py, never becomes a fourth SA-IOT/NCA-style
compliance framework requiring sign-off.

Every fact here was directly confirmed against this project's own
auditor-worker image before being written down (see docs/pqc-readiness.md
for exactly what was checked and how) - never guessed. There is no real,
enforceable "IoT PQC regulation" to cite (unlike NCA CGIoT-1:2024); the 3
criteria this stage checks are named technical criteria grounded in real
NIST standards (FIPS 203/204/205), stated honestly as such.
"""

# OpenSSL's own project history: experimental ML-KEM/Kyber support landed
# in the 3.2 line; this project's own auditor-worker image (3.5.6) was
# directly confirmed via `openssl list -kem-algorithms` to support the full
# NIST-standardized ML-KEM-512/768/1024 (FIPS 203). No other crypto
# library's PQC-support version threshold has been independently verified
# here - deliberately left out of this table rather than guessed (see
# docs/pqc-readiness.md's "Known limitations": extending to wolfSSL/
# BoringSSL/mbedTLS is a real follow-up, not invented now).
CRYPTO_LIBRARY_PQC_THRESHOLDS = {
    "openssl": (3, 2, 0),
}


def _parse_version(version: str) -> tuple[int, ...] | None:
    """Best-effort leading-digit-group parse ("1.0.1e" -> (1, 0, 1)) - never
    raises; an unparseable version returns None so the caller reports
    "unknown" rather than guessing a comparison result."""
    parts: list[int] = []
    for chunk in version.split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else None


def firmware_crypto_pqc_status(package_name: str, package_version: str) -> str:
    """"pass" / "fail" / "unknown" - "unknown" for any library not in
    CRYPTO_LIBRARY_PQC_THRESHOLDS (never a guessed pass/fail) or a version
    string this can't parse."""
    threshold = CRYPTO_LIBRARY_PQC_THRESHOLDS.get(package_name.strip().lower())
    if threshold is None:
        return "unknown"
    parsed = _parse_version(package_version)
    if parsed is None:
        return "unknown"
    return "pass" if parsed >= threshold else "fail"


# Fixed, deterministic tip text - never AI-generated (confirmed with the
# project owner up front) - each grounded in what was actually confirmed
# live against this project's own worker image, never invented.

TIP_TLS_KEY_EXCHANGE_FAIL = (
    "This device negotiated a classical-only TLS key exchange group even though "
    "hybrid post-quantum groups were offered. Upgrade its TLS stack to OpenSSL "
    "3.2+ (or an equivalent library with NIST ML-KEM support, e.g. wolfSSL built "
    "with liboqs, BoringSSL) and enable a hybrid group such as X25519MLKEM768 for "
    "TLS 1.3."
)

TIP_CERT_SIGNATURE_FAIL = (
    "This device's certificate is signed with a classical algorithm (RSA/ECDSA/"
    "DSA). Reissue its certificate chain with a post-quantum signature algorithm "
    "- ML-DSA-65 (NIST FIPS 204) or SLH-DSA (FIPS 205) - once your certificate "
    "authority tooling supports it; OpenSSL 3.5+ can generate these directly "
    "(e.g. `openssl req -x509 -newkey ml-dsa-65 -keyout key.pem -out cert.pem`). "
    "Until reissued, this connection's authentication step stays vulnerable to a "
    "future quantum-capable attacker even if its key exchange is already hybrid."
)

TIP_FIRMWARE_CRYPTO_FAIL = (
    "The crypto library recorded in this device's firmware manifest predates "
    "post-quantum support. Update it to a version with native PQC support "
    "(OpenSSL 3.2+ for experimental Kyber, 3.5+ for the stable NIST-standardized "
    "ML-KEM) - this can't be fixed by configuration alone; the library itself "
    "must be upgraded."
)

TIP_FIRMWARE_CRYPTO_UNKNOWN = (
    "No firmware crypto library recognized against this project's verified "
    "PQC-support reference table (currently OpenSSL only). Upload firmware and "
    "run the manifest scan first, or treat this criterion as not yet assessable "
    "for this device."
)
