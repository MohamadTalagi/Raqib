# ERR-029 — `--open` silently omitted live hosts, making "unknown" dead code

- **Date:** 2026-07-23
- **Component:** policies/catalog/scan_tests.py (`TEST-NET-DISCOVERY`)
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (session work)

## What happened

While tuning the network-discovery scan to be gentler on resource-constrained
IoT devices, live testing against the real lab surfaced a separate,
unrelated accuracy gap: nmap's `--open` flag (used since this test was
first built) suppresses the *entire* per-host report for any live host that
has none of the 6 scanned signature ports open — not just the closed/
filtered port rows within it. That means a real host on the VLAN that's
alive but doesn't run any of `{22,23,80,443,1883,8883}` never appears in the
scan output at all, so the parser's `"unknown"` classification (designed
for exactly "a live host that matches no signature") could never actually
be reached from real nmap output — only from the synthetic examples in its
own unit tests.

## Exact error / symptom

A live run against the real `audit-network` subnet reported "9 hosts up"
in its summary line, but only 6 per-host `Nmap scan report for ...` blocks
appeared in the output — the subnet gateway (`172.30.0.1`), the
`traffic-capture` container, and the scanning `auditor-worker` container
itself (none of which run any of the 6 signature services) were silently
missing entirely, rather than appearing with an empty port table.

## Environment

- nmap 7.95 inside the real `auditor-worker` container against the real
  `audit-network` subnet (172.30.0.0/24).
- Relevant file: `policies/catalog/scan_tests.py::_network_discovery_command`.

## Root cause

`--open` is documented as showing only open ports, but its effect is
coarser than "hide closed/filtered rows" — a host with zero open ports
among the scanned set gets its whole report line dropped, not reduced to an
empty table. Since the parser splits host blocks on `Nmap scan report for`,
a host that never gets that line never becomes a `DiscoveredHost` at all.

## The fix

Dropped `--open` from the command. Every scanned port's state (open,
closed, or filtered) is now printed for every live host, so every live host
gets a report block regardless of whether any signature port is open — the
existing parser already only counts a port as "open" via its own regex
match on the literal word "open", so closed/filtered lines are silently and
correctly ignored without any parser change. Re-verified live: the gateway,
`traffic-capture`, and `auditor-worker` itself now all appear with empty
port tables and correctly classify as `"unknown"` — a genuinely useful
real-world result too, since it's an accurate example of "another network
appliance sharing the VLAN" that isn't an IoT device.

## How to prevent it next time

When a flag's documentation says it filters *output rows*, verify live
whether it actually filters entire *records* instead — the two look
identical in isolated single-host testing (which is all this test's own
unit tests exercised) but diverge exactly in the multi-host, mixed-liveness
case this scan is built for. The existing test
`test_parse_network_discovery_classifies_host_with_no_signature_ports_as_unknown`
was already correct in isolation; it just wasn't exercising a code path the
real command could ever produce until this fix.

## References

- `docs/errors/026` — the other real bug caught via the same live-testing
  pass on this same collector, a parsing regression rather than a command-
  flag issue.
