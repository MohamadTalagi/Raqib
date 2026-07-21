# ERR-023 — tcpdump capture-attach race on Docker Desktop/WSL2

- **Date:** 2026-07-21
- **Component:** auditor-worker (`lab/auditor/worker/scan_scripts/packet_capture.py`, TEST-NET-PKTCAPTURE)
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (session work on the Run Scan 3-section restructure)

## What happened
Building the new "Packet capture" scan test, tcpdump prints its "listening on any, ..." readiness banner to stderr, so the script waited for that exact line before firing the HTTP GET it needed to capture. Live-tested against `device-insecure` on the physical dev machine, the very first run captured 0 packets even though the banner had already appeared.

## Exact error / symptom
```
packets_captured=0
plaintext_get_visible=False
--- packet summary ---
```
A manual timing sweep (fixed delay after the banner, before firing the request) gave 10 packets at 0.5s, 0 at 1.0s, 10 at 1.5s, 0 at 2.0s — non-monotonic, ruling out "just needs a longer wait."

## Environment
- OS / shell: Windows 11, Docker Desktop 29.6.2 with the WSL2 backend
- Tool + version: tcpdump 4.99.5 inside the `auditor-worker` container (`python:3.12-slim` base)
- Relevant files: `lab/auditor/worker/scan_scripts/packet_capture.py`, `lab/auditor/worker/Dockerfile`, `lab/docker-compose.yml`

## Root cause
tcpdump's "listening on" banner prints as soon as the pcap handle opens, but on this platform the capture ring buffer isn't reliably attached to the kernel's packet path by that same instant — there's a short, non-deterministic window where a request that fires right after the banner can complete before the capture is truly live. This looks specific to Docker Desktop's WSL2-virtualized networking rather than a logic bug in the script (a bare Linux host would likely not show this gap).

## The fix
Fire the GET up to 3 times with a short gap (0.4s) instead of once, all inside the same tcpdump session, before stopping the capture. 5/5 trials captured traffic with this approach versus roughly half missing with a single fetch at any fixed delay tried. See `FETCH_ATTEMPTS`/`FETCH_GAP_S` in `packet_capture.py`.

```python
FETCH_ATTEMPTS = 3
FETCH_GAP_S = 0.4
...
for attempt in range(FETCH_ATTEMPTS):
    if attempt:
        time.sleep(FETCH_GAP_S)
    _fetch(host, port, scheme)
```

## How to prevent it next time
Any future "start a capture, then generate one specific packet, then inspect it" test on this stack should assume the readiness banner is necessary but not sufficient, and either retry the generating action a few times or poll the pcap file's growing size before trusting a single attempt. Related: [ERR-017] hit a different Docker Desktop/WSL2 networking quirk (port-forwarding onto `internal: true` networks) — worth checking that file first whenever packet-level behavior on this host looks flaky.

## References
None external — root-caused via a local timing sweep (`docker exec` into `auditor-worker`, varying the post-banner delay and counting captured packets per trial).
