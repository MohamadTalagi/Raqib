"""Compound helper for TEST-NET-PKTCAPTURE.

job_runner.py runs one subprocess per scan job and captures its stdout - it
has no way to orchestrate "start a background capture, then fire a request,
then stop and inspect it" across multiple processes. This script does all of
that internally so it can still be invoked as a single argv command.

The worker is one of the two endpoints of the traffic it captures (its own
request to the device), not a passive network tap: a Docker bridge network
switches by learned MAC address, so a third container can't see another
pair's unicast traffic without ARP spoofing. Capturing on the worker's own
interface while it makes the request is the only capture that reliably works
here - this is why the always-on traffic-capture sidecar (which sits on the
same bridge but isn't a party to worker<->device traffic) can't be reused for
this test.
"""

import os
import re
import select
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

READINESS_TIMEOUT_S = 5
REQUEST_TIMEOUT_S = 5
SETTLE_TIME_S = 0.5
# tcpdump printing its "listening on" readiness banner doesn't guarantee the
# capture ring buffer is actually attached yet on this platform (observed on
# Docker Desktop/WSL2: a single fetch right after the banner sometimes lands
# in a capture gap and yields zero packets, non-deterministically - 5
# repeated trials with one fetch each produced packets on 0/1/2/4 and missed
# on the rest). Firing a few cheap GETs with short gaps closes that window
# reliably (5/5 trials captured traffic) at negligible cost inside the 30s
# job budget.
FETCH_ATTEMPTS = 3
FETCH_GAP_S = 0.4


def _wait_until_capturing(proc: subprocess.Popen) -> None:
    deadline = time.time() + READINESS_TIMEOUT_S
    while time.time() < deadline:
        remaining = max(0.0, deadline - time.time())
        ready, _, _ = select.select([proc.stderr], [], [], remaining)
        if not ready:
            break
        line = proc.stderr.readline()
        if not line or "listening on" in line:
            return


def _fetch(host: str, port: str, scheme: str) -> None:
    url = f"{scheme}://{host}:{port}/"
    context = ssl._create_unverified_context() if scheme == "https" else None
    try:
        if context is not None:
            urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT_S, context=context).read()
        else:
            urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT_S).read()
    except Exception:
        pass  # A refused/errored request is still worth capturing.


def main() -> None:
    host, port, scheme = sys.argv[1], sys.argv[2], sys.argv[3]
    pcap_fd, pcap_path = tempfile.mkstemp(suffix=".pcap")
    os.close(pcap_fd)

    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", "any", "-U", "-w", pcap_path, "host", host, "and", "port", port],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        try:
            _wait_until_capturing(proc)
            for attempt in range(FETCH_ATTEMPTS):
                if attempt:
                    time.sleep(FETCH_GAP_S)
                _fetch(host, port, scheme)
            time.sleep(SETTLE_TIME_S)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        summary = subprocess.run(["tcpdump", "-r", pcap_path, "-nn"], capture_output=True, text=True)
        ascii_dump = subprocess.run(["tcpdump", "-r", pcap_path, "-A"], capture_output=True, text=True)

        packet_lines = [line for line in summary.stdout.splitlines() if line.strip()]
        plaintext_get_visible = bool(re.search(r"GET / HTTP/1\.\d", ascii_dump.stdout))

        print(f"packets_captured={len(packet_lines)}")
        print(f"plaintext_get_visible={plaintext_get_visible}")
        print("--- packet summary ---")
        print(summary.stdout)
    finally:
        try:
            os.unlink(pcap_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
