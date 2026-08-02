"""Compound helper for TEST-TLS-CLIENT-AUTH (NCA 2-4-5, peer authentication).

Detects whether the server's TLS handshake asks for a client certificate at
all (a real CertificateRequest message), regardless of whether any client
actually presents one - that request is the server's own signal that it
authenticates its peers, which is what 2-4-5 actually asks about. `-msg`
prints the raw handshake message trace, so "CertificateRequest" appears as
its own line if and only if the server sent one - a more direct signal than
inferring intent from a "no client certificate CA names sent" string. Fed no
client certificate at all (same as every real client probing this from the
outside), following the same stdin=DEVNULL / subprocess-wrapper precedent
tls_cert_check.py already established for openssl s_client calls in this
codebase.
"""

import subprocess
import sys

HANDSHAKE_TIMEOUT_S = 10


def main() -> None:
    host, port = sys.argv[1], sys.argv[2]
    result = subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-msg"],
        capture_output=True, text=True, timeout=HANDSHAKE_TIMEOUT_S, stdin=subprocess.DEVNULL,
    )
    output = result.stdout + result.stderr
    print("client_cert_requested=" + str("CertificateRequest" in output))


if __name__ == "__main__":
    main()
