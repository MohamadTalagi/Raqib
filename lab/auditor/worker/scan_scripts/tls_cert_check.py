"""Compound helper for TEST-TLS-CONFIG's certificate-validity fields.

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
"""

import re
import subprocess
import sys

HANDSHAKE_TIMEOUT_S = 10
X509_TIMEOUT_S = 5

CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


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
        return
    print("cert_pem_found=True")

    dates = subprocess.run(
        ["openssl", "x509", "-noout", "-dates", "-subject"],
        input=match.group(0), capture_output=True, text=True, timeout=X509_TIMEOUT_S,
    )
    print(dates.stdout)


if __name__ == "__main__":
    main()
