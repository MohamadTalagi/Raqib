"""Unit tests for tls_cert_check.py's forced-protocol-version probe (Week 1
brief gap-closure: "Supported TLS versions" needs a real per-version
enumeration, not just the one protocol a default handshake happens to
negotiate). classify_protocol_probe is a pure function over subprocess
output text, so these need no real network/openssl calls."""

import subprocess
from unittest.mock import patch

from lab.auditor.worker.scan_scripts.tls_cert_check import (
    PROBE_END,
    PROBE_START,
    classify_protocol_probe,
    _probe_protocols,
)


def test_classify_protocol_probe_detects_a_successful_handshake():
    output = "CONNECTION ESTABLISHED\nProtocol version: TLSv1.2\nCiphersuite: ...\nDONE\n"
    assert classify_protocol_probe(output) == "accepted"


def test_classify_protocol_probe_detects_a_real_rejection():
    output = (
        "40D7FC5AA5760000:error:0A00010B:SSL routines:tls_validate_record_header:"
        "wrong version number:../ssl/record/methods/tlsany_meth.c:77:\n"
    )
    assert classify_protocol_probe(output) == "rejected"


def test_classify_protocol_probe_detects_a_client_side_toolchain_limitation():
    # Real error text confirmed live against this project's own auditor-worker
    # image (OpenSSL 3.5.6) when TLSv1/1.1 support is disabled client-side.
    output = (
        "40B72D078F770000:error:0A0000BF:SSL routines:tls_setup_handshake:"
        "no protocols available:../ssl/statem/statem_lib.c:155:\n"
    )
    assert classify_protocol_probe(output) == "untestable"


def test_classify_protocol_probe_treats_an_unrecognized_flag_as_untestable():
    output = "unknown option -tls1\n"
    assert classify_protocol_probe(output) == "untestable"


def test_probe_protocols_runs_all_four_candidates_in_order():
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="Protocol version: TLSv1.3\n", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        results = _probe_protocols("device-hardened", "443")

    assert [label for label, _ in results] == ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    assert [flag for c in calls for flag in c if flag.startswith("-tls1")] == [
        "-tls1", "-tls1_1", "-tls1_2", "-tls1_3",
    ]


def test_probe_protocols_reports_a_timeout_as_rejected_not_a_crash():
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd=command, timeout=8)

    with patch("subprocess.run", side_effect=fake_run):
        results = _probe_protocols("device-hardened", "443")

    assert all(outcome == "rejected" for _, outcome in results)


def test_main_prints_a_delimited_probe_block(capsys):
    from lab.auditor.worker.scan_scripts import tls_cert_check

    def fake_run(command, **kwargs):
        if "-showcerts" in command:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if any(f.startswith("-tls1") for f in command):
            return subprocess.CompletedProcess(command, 0, stdout="Protocol version: TLSv1.2\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="Protocol version: TLSv1.3\nDONE\n", stderr="")

    with patch("sys.argv", ["tls_cert_check.py", "device-hardened", "443"]), \
         patch("subprocess.run", side_effect=fake_run):
        tls_cert_check.main()

    out = capsys.readouterr().out
    assert PROBE_START in out
    assert PROBE_END in out
    assert "TLSv1.2=accepted" in out
    # The probe block must still print even when no certificate PEM is found
    # (the -showcerts phase returned nothing above) - the original script
    # used to `return` early in that case, which would have silently dropped
    # this whole phase.
    assert "cert_pem_found=False" in out
