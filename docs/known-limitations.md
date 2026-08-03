# Known Limitations Register

A single consolidated place for limitations that were previously scattered
across `CLAUDE.md` changelog prose and code comments. Written per the Week 1
brief's explicit request for a "known limitations register." This is the
`SA-IOT-*` assessment pipeline's own register — the separate NCA CGIoT-1:2024
compliance module (`policies/nca/`) has its own limitations section in
`docs/nca-compliance.md`.

## Assessment cancellation

`POST /assessments/{id}/cancel` only prevents **not-yet-started** (`pending`)
child jobs from running; a job already `running` is left to finish rather than
killed mid-execution. Killing an in-flight `subprocess.run` safely would need
process-group tracking `lab/auditor/worker/job_runner.py` doesn't have today.
This is standard "cancel" semantics for already-dispatched work, not a bug,
but it means a cancelled assessment can still show one more job transition to
`recorded`/`failed` after the cancel call returns.

## Collector stdout/stderr

`job_runner.py` concatenates a collector's stdout and stderr into one
`raw_output` string (`raw_output = (result.stdout or "") + (result.stderr or "")`)
rather than preserving them as two distinguishable streams. The content is
fully preserved; only which stream a given line came from is lost.

## Network discovery classification (`TEST-NET-DISCOVERY`)

Classifies each live host on the audit-network subnet as `iot_device`,
`uncertain`, or `unknown` using only its open-port/service signature
(management UI or MQTT port = IoT; Telnet/SSH alone = uncertain, since those
protocols are common to non-IoT network appliances too). Telnet and SSH are
**not** treated as equally strong signals within that "uncertain" bucket:
a Telnet-open host (with or without SSH also open) gets `confidence:
"medium"`, since real IoT/appliance gear still ships Telnet while ordinary
modern Linux/network hosts rarely enable it; an SSH-only host (no Telnet)
stays `confidence: "low"`, since SSH alone is ubiquitous on non-IoT gear too
(any Linux box, a switch, a jump host) and carries little IoT signal on its
own. This lab has a real Telnet-only fixture (`telnet-sim`) to live-verify
the "medium" tier against, but no real SSH-only host — the "low" tier for
that specific case is unit-test-verified only, not live-verified.

MAC address + vendor is now captured as corroborating evidence wherever
nmap's own ARP-based host discovery resolved one (it already ran on every
sweep this project has ever done on the audit-network's local L2 segment;
the parser previously discarded the "MAC Address:" line entirely). Vendor
resolution tries a maintained IEEE OUI (MA-L) registry first
(`lab/auditor/worker/scan_scripts/oui_lookup.py`, fetched/cached and
refreshed on the same low-frequency cadence as Grype's vuln DB and the CISA
KEV feed), falling back to nmap's own smaller/staler bundled guess if the
registry has no match; `mac_vendor_source` records which one actually
answered. **Not** used to drive the classification itself, only surfaced as
additional evidence — this scan runs from inside a Docker bridge network,
where every container shares the host kernel and uses a virtual,
locally-administered MAC address, so a `null`/unresolved vendor is the
correct, expected result for this lab's own fleet, not a lookup failure
(confirmed live: `E8:0A:B9:...` — a real Cisco OUI — resolves to "Cisco
Systems, Inc" from the live-fetched registry, while every one of this lab's
real container MACs correctly resolves to `null`). OS/TTL fingerprinting is
still not used as a corroborating signal, for the same reason. On a real
physical VLAN, MAC vendor data will genuinely help distinguish device types;
treat it as additional evidence there, not as the sole basis for a
classification. An `uncertain` result means the signature set was
inconclusive, not that the host was ruled out as non-IoT — it always needs
manual confirmation.
Restricted to a small, fixed set of signature ports (22, 23, 80, 443, 502,
554, 1883, 8883) rather than a full port sweep across the whole /24, so the
scan finishes reliably and every open port found is one the classifier
actually knows how to interpret; a host running an IoT service on a TCP port
outside this set will show as `unknown` rather than `iot_device`.

**A device that speaks only a UDP discovery protocol, with no TCP signature
port open at all, is no longer invisible to this sweep.** Every
`TEST-NET-DISCOVERY` run also fires nmap's `broadcast-upnp-info` and
`broadcast-dns-service-discovery` NSE scripts (both `broadcast safe`,
live-confirmed on this project's exact nmap 7.95) once per scan — a real IP
that answers either query gets folded into its existing host entry
(`discovery_signals` gains `"upnp_broadcast"`/`"mdns_broadcast"` alongside
`"port_scan"`) or, if it never appeared in the TCP port-scan output at all,
a brand-new `iot_device`/`high`-confidence entry. **Live-verified end to end
for the UPnP path**: this project's own `device-router-gw` fixture answers a
real multicast M-SEARCH and a real client can follow its `LOCATION` header
to fetch a real `description.xml` — the whole real-world UPnP discovery
flow, not just the initial ping. Getting there surfaced two real,
now-fixed bugs, neither hypothetical: (1) neither `device-router-gw`'s SSDP
responder nor `device-speaker`'s mDNS responder ever joined its multicast
group (`IP_ADD_MEMBERSHIP`) — binding to `0.0.0.0` alone only ever receives
unicast/broadcast traffic, never genuine multicast-addressed datagrams, so a
real broadcast query got zero response from either fixture even though this
lab's own existing per-device unicast probes (`TEST-UPNP-PROBE`/
`TEST-MDNS-PROBE`) already worked; (2) `device-router-gw`'s SSDP response
advertised the **requester's** address in its `LOCATION` header instead of
its own, so any real UPnP client (including nmap's own script) that
followed the link to fetch the device description got redirected back to
itself and failed — fixed alongside adding the `/description.xml` endpoint
that never existed at all. **The mDNS/DNS-SD path could not be positively
live-verified**: `broadcast-dns-service-discovery` specifically queries the
DNS-SD service-enumeration convention (`_services._dns-sd._udp.local` PTR),
which `device-speaker`'s intentionally minimal, hand-rolled mDNS responder
(a small raw-socket TXT-record responder, not a full DNS-SD stack, by this
fixture's original design) does not implement — the script correctly and
safely returns nothing against it, a real, honest "no DNS-SD-compliant
device on this scope" outcome, not a bug. The parser for this script's
output is therefore built from nmap's own documented shape, not a positive
live capture, and is unit-test-verified only. Both of this project's own
UDP-only fixtures also happen to expose an HTTP admin UI on port 80, so a
genuinely new (never-seen-via-TCP) host entry has never been produced by a
real scan in this lab either — that specific code path is unit-test-verified
only, matching the same honest caveat this project already carries for a
few other rare branches (e.g. the SSH-only Telnet/SSH confidence tier
above).

**Two-stage execution, so a large configured scope is actually practical.**
The platform's own "adjustable subnets" feature allows configuring a scope
as broad as a /16 (65,534 usable addresses,
`device_validation.MIN_SCOPE_PREFIX_LENGTH = 16`) - a single flat `-sV`
sweep across that many addresses cannot finish in any reasonable timeout,
so `job_runner.py`'s `_run_network_discovery()` instead runs two separate
nmap invocations: **Stage A** is a fast whole-scope `-sn -n` ping/ARP sweep
(no ports, no service detection, no reverse DNS) that only asks "which
addresses are alive"; **Stage B** is the full `-sV` scan (with Task 3's
broadcast scripts) targeted only at the explicit addresses Stage A found
alive, never the whole scope. If Stage A finds zero live hosts, Stage B is
skipped entirely - a real, honest, valid outcome (an empty or misconfigured
scope), not an error. Both stages' raw output is preserved and returned
(clearly separated), never just Stage B's. A Stage A failure (timeout or
exception) fails the whole scan without ever attempting Stage B; a Stage B
failure is reported distinctly from a Stage A failure so it's clear which
phase actually failed.

**Every timeout is an estimate, not a precise measurement, and says so - and
one of them was already revised upward by a real, live-caught surprise, not
a paper calculation.** `estimate_stage_a_timeout()`/`estimate_stage_b_timeout()`
are simple linear formulas (`policies/catalog/scan_tests.py`) with a
generous cap. Stage A's constant is grounded in a real `/24` sweep (10.96s
for 256 addresses at `--max-rate 50` - fast, since every address is
ARP-resolved on a directly-attached L2 segment) but padded well beyond a
naive extrapolation of that number, because **an attempted large-scope
live-verification pass surfaced a real, only partially understood anomaly**:
adding a genuinely unrouted RFC1918 `/20` (4,094 addresses - nothing in this
Docker lab's topology actually routes to it) as a second active scope and
sweeping it alongside the real audit-network `/24` did not finish within 554
seconds before being killed - the real job this reproduces (network scan
#17) had already failed with a genuine `"discovery phase (Stage A) timed out
after 227s"` error against this project's *first-draft* estimate for that
same combined scope. A follow-up isolated check of a *much* smaller unrouted
range (a `/27`, 32 addresses) came back quickly (6.12s) but with **every
single address falsely reported "up"** - none of them carrying a real "MAC
Address:" line the way this lab's genuine ARP-resolved hosts always do,
meaning these were not real ARP-confirmed hosts. The most likely explanation
is some form of NAT/routing-reflection behavior specific to this Docker
Desktop test host's own networking layer for a destination with no real
route at all - not something this task's own scope covers root-causing, and
not confirmed as representative of how a real, physically routed (even if
mostly idle) enterprise VLAN would behave. **The honest, safe response to an
unresolved anomaly was a substantially larger, more conservative constant
and a much higher cap** (`STAGE_A_MAX_SECONDS` raised from 3600 to 7200),
not a confident recalculation built on a data point that isn't fully
understood. **What *was* cleanly live-verified**: the real, always-supported
case - a sweep scoped to only the real audit-network `/24` (no synthetic
scope added) - produced byte-for-byte-equivalent classification/
discovery-signal results, via the real two-stage command chain, to the
single-stage sweep this replaced (network scan #18, after the constants
revision), confirming the two-stage *architecture* itself is correct even
though the *timeout tuning* needed a real correction first. **What remains
genuinely unverified, stated plainly rather than implied**: Stage B's
behavior at true large-live-host-count scale (this lab cannot spin up
hundreds of real live hosts); a real full `/16` sweep end to end (per the
finding above, a scope-summed-address timeout at that size now falls back to
the 7200s cap rather than a number this project has confidently derived);
and, most importantly, **whether Stage A can be trusted not to over-report
live hosts on a scope with unusual routing/NAT behavior** - the `/27`
false-positive-storm finding above is a real, live-observed risk to this
design's own core assumption (that Stage B only ever targets addresses
genuinely confirmed alive) that was not resolved within this task and should
be treated as a real, open follow-up, not a settled matter. One structural
mitigation already in place, worth noting: because `estimate_stage_b_timeout()`
scales with however many "live" hosts Stage A reports, a false-positive
storm would make Stage B slower and more expensive, not silently wrong or
unbounded - the system degrades rather than breaks, even in this
unconfirmed failure mode.

**Deliberately tuned gentle, not fast**, because this is an IoT environment
and real devices can have weak network stacks: `-T3` (Normal) rather than
`-T4` (Aggressive, which nmap's own docs say assumes "a reasonably fast and
reliable network"), `--max-rate 50` to cap the packet rate so no burst can
flood a fragile target, and `--version-intensity 2` for lighter service-
fingerprinting probes (default is 7) since the classifier only needs the
port number, not a deep fingerprint. Verified live that this costs no real
time in this lab (~25s either way — the dominant factor for a /24 sweep is
the mostly-silent host-discovery phase, not per-host probe aggressiveness),
so this test's job-level timeout was still raised to 90s (from the 30s
default every other test uses) purely for headroom, not because the gentler
settings made it slower here. `--open` was deliberately **not** used
(removed after `docs/errors/029` found it silently omitted every live host
with none of the signature ports open — e.g. the subnet gateway — collapsing
the `"unknown"` classification into dead code); every scanned port's real
state is always printed, and the parser ignores anything that isn't
literally "open."

## Per-control coverage gaps

Each of the 5 `SA-IOT-*` controls' YAML now carries a `limitations` field
describing exactly what it does and doesn't check (surfaced in every report
format). In summary:

- **SA-IOT-001** (device identification): only checks that a device-info
  endpoint discloses vendor/model/firmware — doesn't verify the values are
  accurate. `TEST-DEVICE-ID` has no automated collector wired into
  `SCAN_CATALOG` at all yet, so this control is never automatically
  evaluated in practice; it stays unassessed (not `NOT_APPLICABLE` — see
  below) until a real collector is built for it.
- **SA-IOT-002** (default credentials): only tries 10 commonly documented
  default pairs against an HTTP(S) login form — no brute force, no
  SSH/Telnet/MQTT credential checking.
- **SA-IOT-003** (unnecessary services): only the Telnet-specific
  pass/fail condition is automated; a full port scan runs and records every
  open port, but other unnecessary services need manual review of the same
  output.
- **SA-IOT-004** (insecure protocols): only evaluates MQTT, not any other
  protocol a device might use.
- **SA-IOT-005** (TLS configuration): checks key strength and protocol
  version only — not certificate expiry, hostname/CN matching, or full
  chain-of-trust validation (a separate, real `cert_expired` field was added
  to `TEST-TLS-CONFIG`'s observations for expiry specifically, but SA-IOT-005
  doesn't currently key its verdict on it).

## NOT_APPLICABLE vs. "not yet automated"

`policies/engine/policy_engine.py::is_control_applicable()` deliberately
treats a required test_id with **no entry in `SCAN_CATALOG` at all** as
"possibly applicable" (never `NOT_APPLICABLE`) — an absent collector tells us
nothing about whether a control genuinely doesn't apply to a device's
registered services, only that nobody has automated it yet. `NOT_APPLICABLE`
is reserved for controls whose required test_ids **do** exist in
`SCAN_CATALOG` but whose `applicable_service_types` never match any of the
device's registered services (e.g. SA-IOT-004/MQTT against an HTTP-only
device). Getting this distinction wrong was caught live against the real
dev database during this session — see `docs/errors/025-not-applicable-confused-with-not-automated.md`.

## Evidence conflict detection

`policies/engine/conflict.py::detect_conflict()` only detects disagreement on
the specific field(s) a control's own `pass`/`fail` conditions key on — two
evidence rows that disagree on an unrelated observation field are not
flagged as conflicting. When a real conflict is found, the row with
`source_type == "automated"` always wins over `"manual"`/`"document"` rows;
among multiple automated rows (or no automated row at all), the most recent
timestamp wins. There's no separate manual "which one is right" override —
conflict resolution is always automatic once evidence is recorded.

## Reviewer identity is not authentication

This entire application has no login, session, or user/role concept
anywhere. Nothing in the Week 1 `SA-IOT-*` pipeline requires a reviewer name
(that requirement applies to the separate NCA module's manual
assessments/exceptions — see `docs/nca-compliance.md`).

## Report formats

- The HTML report (`GET /devices/{id}/report.html`) inlines the same
  stylesheet the PDF uses, but its `@font-face` `url()`s stay relative and
  won't resolve from an API route path — the browser falls back to a system
  font. Cosmetic only; every value in the document is identical real data.
- Policy version tracking (`compliance_assessments.policy_version` /
  `verdicts.policy_version`) is recorded per assessment/verdict at the time
  it's created, taken from the control YAML's own `version:` field. There is
  no mechanism yet to diff two policy versions against each other or show
  what changed between them.

## Vulnerability intelligence is snapshot-based, not live-real-time

`TEST-FW-MANIFEST`'s CVE/CISA-KEV data (see `docs/vulnerability-intelligence.md` for
the full write-up) comes from Grype's local vulnerability database, refreshed by the
worker on a schedule (default: check every 6h, refresh if the last successful refresh
is over 7 days old) — not fetched live at scan time. A finding is only ever as current
as the last successful `grype db update`; `observations.vuln_db_built_at` on each
firmware-manifest evidence record says exactly which snapshot produced it, and
`GET /vuln-intel/status` / the dashboard's freshness note report the same thing. Only
`TEST-FW-MANIFEST` evidence carries this data — `TEST-NET-HTTP-INSPECT`'s Server-banner
enrichment stayed on the older, much smaller static reference table.

## Dynamic risk scores are self-reported for two of their seven inputs

`GET /risk/devices/{id}` (see `docs/risk-assessment.md` for the full write-up)
combines compliance, CVSS, exploit availability, device criticality, internet
exposure, violation count, and insecure-service count into one score. Two of those
seven — criticality and exposure — are auditor-set fields
(`devices.criticality`/`devices.exposure`) with a computed starting default, not
something any scan can verify; the score is only as accurate as whoever last
reviewed them. The score itself never feeds back into or auto-flips a compliance
verdict, by design.

## Clean-deployment smoke test

`scripts/smoke_test.sh` brings the stack up and polls Docker health checks
plus a few HTTP endpoints; it does not (by default) tear down and remove
volumes first, since that would destroy real seeded data. Pass `--fresh` for
a true from-nothing deployment test — but never against a stack whose data
you want to keep.
