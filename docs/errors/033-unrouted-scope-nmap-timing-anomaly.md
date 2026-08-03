# ERR-033 — Unrouted large-scope proxy causes nmap ping-sweep timing anomalies (unresolved)

- **Date:** 2026-08-03
- **Component:** policies/catalog/scan_tests.py (`estimate_stage_a_timeout`) / lab/auditor/worker/job_runner.py (`_run_network_discovery`)
- **Severity:** medium (mitigated by a conservative timeout, not root-caused)
- **Status:** open
- **Author:** Claude (Task 4, Network Discovery precision & scale hardening plan)

## What happened

Task 4 built two-phase (Stage A ping sweep / Stage B targeted service scan)
network discovery so a large configured scope (this platform allows up to a
/16) doesn't need a single flat `-sV` sweep. To live-verify Stage A's
timeout formula at something larger than this lab's real /24, an unused
RFC1918 range was added as a second active Network Scope (nothing in this
Docker lab's actual topology routes to it - a "closest available proxy for
a large empty scope," per the implementation plan's own suggestion).

The first attempt (`10.55.0.0/20`, 4,094 addresses, added alongside the
real audit-network `/24`) did not behave like an "empty scope": a real
`POST /network-scans` job against it genuinely timed out
(`"discovery phase (Stage A) timed out after 227s"`, network scan #17,
against this task's own first-draft timeout estimate), and a follow-up raw
`nmap -sn -n --max-retries 1 --max-rate 50` run against the same combined
scope was manually killed after 554+ seconds without finishing - far past
what a `total_addresses / --max-rate` model predicts (~87s theoretical
minimum for 4,348 addresses at 50 pps).

A smaller isolated follow-up (`10.55.0.0/27`, 32 addresses, same unrouted
range) completed quickly (6.12s) but with a different, equally surprising
result: **every single address came back "Host is up"** - a 100%
false-positive rate, since none of them carried a real "MAC Address:" line
(this lab's genuine ARP-resolved hosts always do).

## Exact error / symptom

```
# Real job failure (network scan #17):
{"status": "failed", "error": "discovery phase (Stage A) timed out after 227s"}

# Raw command, killed after 554+s with zero output for the /20 portion:
nmap -sn -n --max-retries 1 --max-rate 50 172.30.0.0/24 10.55.0.0/20

# Isolated /27 check - fast, but every address falsely "up":
nmap -sn -n --max-retries 1 --max-rate 50 10.55.0.0/27
Nmap done: 32 IP addresses (32 hosts up) scanned in 6.12 seconds
```

## Environment

- OS / shell: Windows 11 host, Docker Desktop (WSL2 backend)
- Tool + version: nmap 7.95, inside the real `auditor-worker` container
- Relevant files: `policies/catalog/scan_tests.py`, `lab/auditor/worker/job_runner.py`, `lab/auditor/api/network_scope_routes.py`

## Root cause

Not conclusively determined within this task's scope. The leading
hypothesis: `10.55.0.0/*` has no real route from the `auditor-worker`
container (its only two interfaces are `172.30.0.0/24` and
`172.31.0.0/24`; the default route goes via the audit-network gateway).
Traffic toward an address with no real destination likely gets absorbed or
reflected somewhere in Docker Desktop's own host-networking/NAT layer
(dockerd's userland proxy, WSL2's virtual switch, or iptables MASQUERADE on
the host) in a way that:
- for a small burst (32 addresses), comes back fast but generates a
  positive-looking signal for every address (no ICMP/ARP evidence, so
  probably a TCP RST or similar reflected back for nmap's default port-80/
  443 SYN probes, which nmap's `-sn` logic treats as "host up, port
  closed" rather than "host down");
- for a much larger burst (4,094 addresses), degrades into something that
  does not complete in any reasonable time at all - possibly the same
  reflection mechanism under real load behaves completely differently
  (rate-limited, queued, or dropped by the host's own network stack).

This may be entirely specific to this Docker Desktop test host's own
network stack and not representative of how a real, physically routed
(even if mostly idle) enterprise VLAN would behave - a real deployment
would have actual L2/L3 connectivity to its configured scope, not a
completely fictional, unrouted CIDR. But it was not possible to construct
a "real but empty" proxy inside this lab's actual Docker topology to test
that distinction (nothing in this lab is both large and genuinely routed).

## The fix

No real fix — a mitigation only. `STAGE_A_PER_ADDRESS_SECONDS` was raised
from `0.05` to `0.3` and `STAGE_A_MAX_SECONDS` from `3600` to `7200`
(`policies/catalog/scan_tests.py`), based on the real (if not fully
understood) worst-case data point above, rounded generously up rather than
recalculated with false confidence. The real, always-supported case (a
sweep scoped to only the real audit-network `/24`, no synthetic scope) was
re-verified live end to end with the new constants and reproduced
byte-for-byte-equivalent results to the single-stage sweep this replaced
(network scan #18) — the two-stage *architecture* is confirmed correct;
only the *timeout tuning* needed the real-data-driven correction.

One structural mitigation already present, not newly added: because
`estimate_stage_b_timeout()` scales with however many hosts Stage A
reports as live, a false-positive storm (per the `/27` finding) would make
Stage B slower and more expensive, not silently wrong or unbounded — a
degradation, not a crash, even in this unconfirmed failure mode.

```python
# policies/catalog/scan_tests.py
STAGE_A_BASE_SECONDS = 15            # was 10
STAGE_A_PER_ADDRESS_SECONDS = 0.3    # was 0.05
STAGE_A_MAX_SECONDS = 7200           # was 3600
```

## How to prevent it next time

- Do not trust a synthetic/unrouted CIDR as a stand-in for "a real large
  but mostly-empty subnet" without first confirming the test environment
  routes to it the way a real network would (e.g. get a real negative
  ICMP/ARP signal, not silence or a reflection artifact).
- If this platform is ever deployed against a genuinely large real scope,
  watch the very first real Stage A run closely (its raw output, its
  actual duration vs. the estimate) rather than assuming the estimate is
  trustworthy at that scale - it explicitly is not, and says so in its own
  docstring and `docs/known-limitations.md`.
- A more rigorous follow-up (out of scope for this task): reproduce this
  anomaly outside Docker Desktop (a real Linux host, or a cloud VM with
  real routing) to determine whether it's a Docker-Desktop-specific
  artifact or a real nmap/`-sn` behavior worth hardening against generally
  (e.g. an explicit `--host-timeout` bound, verified not to introduce
  false negatives).

## References

- `docs/superpowers/plans/2026-08-03-network-discovery-precision-and-scale.md` (Task 4)
- `docs/known-limitations.md` ("Two-stage execution" / "Every timeout is an estimate" sections)
