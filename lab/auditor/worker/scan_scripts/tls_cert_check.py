"""Compound helper for TEST-TLS-CONFIG's certificate-validity fields, plus a
per-protocol-version support probe.

job_runner.py runs one subprocess and captures its stdout; getting a
certificate's notBefore/notAfter dates needs a second openssl invocation fed
a PEM certificate on stdin - not expressible as a single argv command
without a shell pipe, which this project never uses (fixed commands, no
shell=True, per device_validation's own threat model). Also, in practice,
`-brief` suppresses the certificate PEM even together with `-showcerts` -
confirmed live against this lab's own device-hardened, verified before
writing this comment - so getting both means two separate handshakes:

  1. `-brief` (unchanged from the original single-command behavior, printed
     first) - _parse_tls_observations's existing weak_cipher/tls_version
     parsing keys on this exact output shape and is untouched.
  2. `-showcerts` without `-brief`, purely to obtain the PEM, fed into a
     third `openssl x509 -noout -dates` call whose output is appended.

A third phase then forces a handshake at each of TLSv1/1.1/1.2/1.3 in turn
(Week 1 brief, task 3: "Supported TLS versions" - the original single
default-negotiated `tls_version` field only ever reports the one protocol a
server and client happened to agree on, not which versions the server
actually accepts). Each attempt is classified into one of three states,
never collapsed to two - confirmed live against this lab's own worker image
that a real, distinct failure mode exists: this environment's own OpenSSL
3.x build refuses to even *offer* TLSv1/1.1 by default (`no protocols
available`), which is a client-side limitation, not a server signal, and
must not be reported as "the server rejected TLSv1.1" when the truth is
"this probe couldn't test TLSv1.1 here at all".
"""

import re
import subprocess
import sys

HANDSHAKE_TIMEOUT_S = 10
X509_TIMEOUT_S = 5
PROTOCOL_PROBE_TIMEOUT_S = 8

CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

# (label, openssl flag) - the four protocol versions a device's TLS config
# might expose or restrict. SSLv3 is deliberately excluded: it predates
# every device this lab simulates and modern openssl builds often can't even
# link it in, which would make every probe "untestable" rather than useful.
PROTOCOL_CANDIDATES = [
    ("TLSv1", "-tls1"),
    ("TLSv1.1", "-tls1_1"),
    ("TLSv1.2", "-tls1_2"),
    ("TLSv1.3", "-tls1_3"),
]

PROBE_START = "PROTOCOL_PROBE_START"
PROBE_END = "PROTOCOL_PROBE_END"


def classify_protocol_probe(output: str) -> str:
    """One of "accepted" / "rejected" / "untestable" - never conflated.

    Matches the exact same string-based approach _parse_tls_observations
    already uses for the default handshake (no returncode check - a `-brief`
    handshake given no stdin can exit non-zero even on a real successful
    negotiation, since the server sees EOF and closes first).

    A connection-level failure (target unreachable, connection refused) is
    also "untestable", not "rejected" - the probe never got far enough to
    ask the server anything about this protocol version at all, which is a
    different, honest state from the server explicitly negotiating some
    other version instead. "connect:errno" is openssl's own real error
    string on a failed connect() in this project's Linux worker image."""
    lowered = output.lower()
    if (
        "no protocols available" in lowered
        or "unknown option" in lowered
        or "invalid command" in lowered
        or "connect:errno" in lowered
    ):
        return "untestable"
    if "protocol version:" in lowered:
        return "accepted"
    return "rejected"


def _probe_protocols(host: str, port: str) -> list[tuple[str, str]]:
    results = []
    for label, flag in PROTOCOL_CANDIDATES:
        try:
            attempt = subprocess.run(
                ["openssl", "s_client", "-connect", f"{host}:{port}", "-brief", flag],
                capture_output=True, text=True, timeout=PROTOCOL_PROBE_TIMEOUT_S, stdin=subprocess.DEVNULL,
            )
            outcome = classify_protocol_probe(attempt.stdout + attempt.stderr)
        except subprocess.TimeoutExpired:
            # A network hang is not "the server rejected this version" - the
            # probe simply never got an answer at all, the same honest
            # "untestable" state as a connection failure or a client-side
            # limitation above, not the stronger claim that a response was
            # observed and it declined this specific version.
            outcome = "untestable"
        results.append((label, outcome))
    return results


def main() -> None:
    host, port = sys.argv[1], sys.argv[2]

    brief = subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-brief"],
        capture_output=True, text=True, timeout=HANDSHAKE_TIMEOUT_S, stdin=subprocess.DEVNULL,
    )
    print(brief.stdout)
    print(brief.stderr)

    with_certs = subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-showcerts"],
        capture_output=True, text=True, timeout=HANDSHAKE_TIMEOUT_S, stdin=subprocess.DEVNULL,
    )
    match = CERT_RE.search(with_certs.stdout + with_certs.stderr)
    if not match:
        print("cert_pem_found=False")
    else:
        print("cert_pem_found=True")
        dates = subprocess.run(
            ["openssl", "x509", "-noout", "-dates", "-subject"],
            input=match.group(0), capture_output=True, text=True, timeout=X509_TIMEOUT_S,
        )
        print(dates.stdout)

    print(PROBE_START)
    for label, outcome in _probe_protocols(host, port):
        print(f"{label}={outcome}")
    print(PROBE_END)


if __name__ == "__main__":
    main()
