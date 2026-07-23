# ERR-026 — `\s+` in a port-table regex swallowed the next port's whole line

- **Date:** 2026-07-23
- **Component:** policies/catalog/scan_tests.py (`TEST-NET-DISCOVERY`)
- **Severity:** high
- **Status:** resolved
- **Author:** Claude (session work)

## What happened

While adding a new network-discovery scan (`TEST-NET-DISCOVERY`, a subnet-wide
nmap sweep that classifies each live host as an IoT appliance / uncertain /
unknown from its open-port signature), the parser's per-host port-table regex
was written with `\s+` instead of `[ \t]+`. Verified live against the real
lab, `device-insecure` — which genuinely exposes Telnet (no version string)
immediately followed by HTTP (with a version string) — came back classified
as `uncertain` instead of `iot_device`, and its `open_ports` list was missing
port 80 entirely.

## Exact error / symptom

Raw nmap output for the host (real, from the live worker):

```
PORT   STATE SERVICE VERSION
23/tcp open  telnet?
80/tcp open  http    Uvicorn
```

Parsed observation for that host (wrong):

```json
{
  "open_ports": [23],
  "services": [{"port": 23, "service": "telnet?", "version": "80/tcp open  http    Uvicorn"}],
  "classification": "uncertain"
}
```

Port 80 never became its own entry — its entire line was absorbed as port
23's "version" text.

## Environment

- nmap 7.95, Python 3.12, running inside the real `auditor-worker` container
  against the real `audit-network` subnet (172.30.0.0/24).
- Relevant file: `policies/catalog/scan_tests.py`,
  `_parse_network_discovery_observations`.

## Root cause

The regex was `r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+?))?\s*$"` with
`re.MULTILINE`. `\s` matches `\n` as well as spaces/tabs. When a port line
has no version text at all (nmap prints just `23/tcp open  telnet?` with
nothing after the service name), the optional group's leading `\s+` can
match the newline itself, and the non-greedy `(.+?)` then starts consuming
the *next* line's real content as if it were this port's version — `.`
doesn't cross a `\n`, so it stops at the end of that next line, producing
exactly the corrupted single-match result above instead of two separate
matches.

`_parse_nmap_observations` (`TEST-NET-PORTSCAN`, added earlier) already
avoids this exact trap by using `[ \t]+`/`[ \t]*` instead of `\s+`/`\s*` —
the new function was written without noticing that established pattern.

## The fix

```python
# before
r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+?))?\s*$"
# after
r"^(\d+)/tcp[ \t]+open[ \t]+(\S+)(?:[ \t]+(.+?))?[ \t]*$"
```

Re-ran the same live scan afterward: `device-insecure` correctly showed
`open_ports: [23, 80]` and classified as `iot_device` (via port 80), while
`telnet-sim` (genuinely Telnet-only, no other signature port) still
correctly classified as `uncertain` — the exact "distinguish an IoT
appliance from another network appliance on the same VLAN" behavior this
test exists for.

## How to prevent it next time

Never use bare `\s+`/`\s*` inside a per-line regex applied to multi-line
tool output under `re.MULTILINE` unless deliberately intending to span
lines — use `[ \t]+`/`[ \t]*` for "whitespace within one line." Added a
regression test
(`test_parse_network_discovery_does_not_swallow_the_next_port_when_one_has_no_version`,
`policies/catalog/test_scan_tests.py`) using exactly this
no-version-then-versioned shape, since every other test case in the same
file only ever exercised a single port per host and would not have caught
this.

## References

- `policies/catalog/scan_tests.py::_parse_nmap_observations` — the existing,
  already-correct sibling parser this should have matched from the start.
