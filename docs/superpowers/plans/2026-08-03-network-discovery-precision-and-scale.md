# Network Discovery: Precision & Scale Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three gaps a code review flagged in `TEST-NET-DISCOVERY` (the VLAN-sweep collector behind the Devices page's "Discover devices" panel and `POST /network-scans`): a precision loss in how it classifies Telnet vs. SSH, a hardcoded timeout that cannot survive the subnet sizes the platform itself now allows, and three named "missing" capabilities (Scapy/ARP discovery, MAC-vendor/OUI lookup, SSDP/mDNS folded into the primary sweep).

**Origin:** A prior review pass on this project left the note:

> "AMBIGUOUS_PORTS = {22, 23} conflates SSH — common on almost anything — with Telnet, a much stronger insecure-IoT signal, into one confidence tier: a real precision loss. The 90s sweep timeout is hand-tuned for a /24 and won't scale to a larger subnet without a different strategy. Missing: No Scapy/ARP-based discovery (named in docs/reference/IoTGuard.md, absent from code), no MAC-vendor/OUI lookup, no SSDP/mDNS folded into the primary sweep."

Every claim in that note was independently re-verified against the real code and a real (throwaway, `python:3.12-slim` + `apt install nmap`) container matching the exact `auditor-worker` base image before writing this plan — see "Grounding" below. One claim needed correcting in the process: this is **not** "missing Scapy/ARP discovery" in the sense of "no ARP discovery happens at all" — nmap already performs real ARP-based host discovery for the audit-network's directly-attached L2 segment, proven by this project's own committed evidence file. The actual gap is that the parser throws that signal away. The plan below fixes the real gap rather than bolting on a redundant hand-rolled ARP scanner.

Two design decisions in this plan were confirmed with the project owner up front (2026-08-03), each choosing the more thorough of two real options:
1. **Subnet-scale strategy: two-phase discovery** (fast ping/ARP sweep across the whole configured scope, then a full port/service scan only against hosts found alive), not a bigger static timeout constant. This is the one piece of the plan with real architectural blast radius — it changes `job_runner.py`'s execution model for this one test.
2. **OUI vendor lookup: a maintained IEEE OUI registry fetch/cache** (`oui_lookup.py`, mirroring `cisa_kev.py`'s existing fetch/cache pattern), not just surfacing nmap's own bundled (smaller, staler) vendor guess as-is.

**Tech stack:** Python (`policies/catalog/scan_tests.py`, `lab/auditor/worker/job_runner.py`), nmap 7.95 (already the worker image's real installed version — confirmed live), `requests` (already a worker dependency, used identically by `cisa_kev.py`), React/TypeScript (`lab/auditor/web`), pytest/Vitest.

---

## Grounding — what was verified before designing anything

- **`AMBIGUOUS_PORTS = frozenset({22, 23})`** — `policies/catalog/scan_tests.py:393`. `_classify_host()` (line 429) gives Telnet-only, SSH-only, and Telnet+SSH the *identical* `("uncertain", "low", ...)` result today. Confirmed by reading the function directly, not inferred.
- **The 90s timeout** — `SCAN_CATALOG["TEST-NET-DISCOVERY"]["timeout_seconds"] = 90` (line 1409), a static int read once via `spec.get("timeout_seconds", COMMAND_TIMEOUT_SECONDS)` in both `job_runner.py:164` (`process_job`) and `job_runner.py:237` (`process_network_scan`, the real path the Devices-page "Discover devices" panel uses).
- **Subnets are genuinely configurable up to a /16 today**, not just a /24: `lab/auditor/api/network_scope_routes.py` + `device_validation.MIN_SCOPE_PREFIX_LENGTH = 16` (`device_validation.py:48`), added in the most recent commit before this session (`984864f "Add adjustable subnets"`). A /16 is 65,534 usable addresses — confirming the review's "won't scale" claim is a live, reachable condition today, not a hypothetical.
- **ARP-based discovery already happens** — real committed evidence `document-store/raw/EV-2026-07-23-0001.txt` (a real `TEST-NET-DISCOVERY` run against this lab's own audit-network) shows nmap emitting `MAC Address: E6:4D:1A:E6:45:D7 (Unknown)` for every discovered host. nmap only prints a MAC Address line when it resolved the host via ARP on a directly-attached Ethernet segment — this is nmap's own built-in ARP host-discovery mechanism already firing, using its own bundled `nmap-mac-prefixes` OUI database (which returns "Unknown" here because Docker assigns each container a virtual, locally-administered MAC address — not because the technique didn't run). `_parse_network_discovery_observations()` (`scan_tests.py:459`) parses only `PORT/tcp open ...` lines and silently discards this MAC Address line entirely — confirmed by reading the regex, which has no MAC-address pattern at all.
- **nmap 7.95 (the exact version this project's own evidence shows) really does ship the two broadcast NSE scripts this plan needs** — verified live in a throwaway container built the same way the worker `Dockerfile` builds it (`python:3.12-slim` + `apt-get install nmap`):
  ```
  Nmap version 7.95 ( https://nmap.org )
  ...
  broadcast-dns-service-discovery.nse
  broadcast-upnp-info.nse
  dns-service-discovery.nse
  upnp-info.nse
  ```
  `nmap --script-help broadcast-upnp-info,broadcast-dns-service-discovery` confirms both are categorized `broadcast safe` and need no script-args — consistent with this project's existing "safe/gentle" scanning posture.
- **Confidence is currently a closed 2-value type** — `lab/auditor/web/src/lib/types.ts:142`: `confidence: "high" | "low"`. Confirmed no frontend code renders this field today (`grep`'d `NetworkDiscoveryPanel.tsx` — it only renders `classification` via a badge and `rationale` as free text), so widening this union to add a third value is additive with no UI breakage.
- **`docs/known-limitations.md`'s "Network discovery classification" section already names two of these three gaps as deliberate, documented, future work** ("On a real physical VLAN, both should be added as additional evidence" re: MAC-vendor/OS fingerprinting; the UDP-only 1900/5353 gap is called "a real, documented scope limitation, not an oversight"). This plan is the follow-through that document already invited, not a new direction.
- **This lab already has real UDP-only IoT fixtures to verify Fix 4 against**: `device-router-gw` (UPnP/SSDP responder on 1900/udp) and `device-speaker` (mDNS responder on 5353/udp) — both built in the 2026-08-02 five-device-fixture session, both currently only reachable via their own per-device `TEST-UPNP-PROBE`/`TEST-MDNS-PROBE` unicast collectors, never via the subnet-wide sweep.

---

## Global Constraints

- **No behavior change to the existing 3-value `classification` enum** (`iot_device` / `uncertain` / `unknown`) — every fix in this plan refines *confidence* and *rationale* and *observation fields*, never invents a 4th classification bucket, so nothing downstream that already branches on those 3 strings needs to change.
- **Never overclaim.** Every new signal (MAC vendor, broadcast-script hits) must degrade honestly to "unknown"/absent when it can't resolve something, exactly like every existing collector in this codebase. A Docker-lab "Unknown" vendor is a correct, expected result, not a bug to paper over.
- **Reuse over reinvention.** No hand-rolled ARP/Scapy code, no hand-rolled OUI table with no refresh path — reuse nmap's own built-in ARP discovery and NSE scripts, and mirror `cisa_kev.py`'s already-proven fetch/cache architecture for the new OUI lookup, exactly as this project has always preferred wiring in an existing verified tool (Grype, Syft, nmap NSE scripts for Modbus/RTSP) over hand-rolling protocol logic.
- **`scan_tests.py` stays pure.** `build_command`/`parse_observations` functions there take/return plain data and never call `subprocess`, `requests`, or touch the filesystem beyond what already exists (`vuln_reference.py`-style static lookups are fine; live network fetches are not). All process-execution and orchestration for the new two-stage flow lives in `job_runner.py`, matching the existing module boundary stated in `scan_tests.py`'s own docstring.
- **Gentle-scanning posture is non-negotiable.** Every new nmap invocation (Stage A's ping sweep included) keeps `--max-rate 50`/`-T3`-equivalent gentleness — this was a hard-won, live-verified decision (docs/errors/029 and the surrounding changelog entries) and nothing in this plan should quietly regress it for a speed win.
- **Every new/changed timeout formula must be labeled honestly as an estimate** where it hasn't been live-measured (this project has only ever live-measured a /24 sweep, ~25s for 9 hosts / 256 addresses) — comments and `docs/known-limitations.md` must say so, not imply a precision this plan doesn't have yet.
- Python: 4-space indent, type hints on new functions, no emojis. Commands stay argv lists (never shell strings) — the existing security boundary.
- Follow this project's own established rollout discipline: implement in the 4 phases below in order, run the full relevant regression suite after each, and do a real **live** verification pass (real lab containers, not just mocks) before considering a phase done — matching every prior phase in this project's history.

---

## File Structure

**Created:**
- `lab/auditor/worker/scan_scripts/oui_lookup.py` — fetch/cache the IEEE public OUI (MA-L) registry, mirrors `cisa_kev.py`'s shape exactly (fetch, local cache file, staleness check, graceful fallback).
- `lab/auditor/worker/scan_scripts/test_oui_lookup.py` — unit tests (mocked HTTP, cache staleness, fallback-to-nmap-guess path).
- `docs/errors/0NN-...md` — for any real bug this plan's live-verification pass catches (per this project's mandatory error-log convention), filled in as needed, not pre-written.

**Modified:**
- `policies/catalog/scan_tests.py` — `_classify_host()` split logic; new MAC-address regex + parsing in `_parse_network_discovery_observations()`; new `_network_discovery_stage_a_command()` / `_parse_stage_a_live_hosts()` / `_network_discovery_stage_b_command(live_hosts)` pure functions; new `estimate_stage_a_timeout()` / `estimate_stage_b_timeout(live_host_count)`; broadcast-script args added to Stage B's command; new broadcast-script-result parsing folded into the existing per-host `hosts` list.
- `lab/auditor/worker/job_runner.py` — new shared `_run_network_discovery()` two-stage orchestration, called from both `process_job()`'s and `process_network_scan()`'s `TEST-NET-DISCOVERY` branches; wires in `oui_lookup.py`'s fetch/cache refresh into the existing periodic-refresh poll pattern (`maybe_refresh_grype_db`/`maybe_refresh_network_scope` precedent).
- `policies/catalog/test_scan_tests.py` — updated/new unit tests for every fix below.
- `lab/auditor/worker/test_job_runner.py` — new two-stage orchestration tests.
- `lab/auditor/web/src/lib/types.ts` — `confidence: "high" | "medium" | "low"`; `DiscoveredHost` gains optional `mac_address`, `mac_vendor`, `mac_vendor_source` ("ieee_registry" | "nmap_bundled" | null), and a `discovery_signals` list (e.g. `["port_scan", "upnp_broadcast"]`) so the UI can show *how* a host was found, not just its final classification.
- `lab/auditor/web/src/components/devices/NetworkDiscoveryPanel.tsx` — render MAC vendor (when present) and a small "found via UPnP/mDNS broadcast" indicator alongside the existing rationale text.
- `docs/known-limitations.md` — rewrite the "Network discovery classification" section's now-stale sentences ("Deliberately does not use MAC-vendor (OUI) lookup...", the 1900/5353 TCP-only caveat) to describe the new real coverage, and add the new honest caveats this plan introduces (timeout-formula-is-an-estimate-above-/24, SSH-only-tier has no live fixture to test against in this lab).
- `policies/catalog/scan_tests.py`'s own header-comment block (lines ~380–391, the `IOT_SIGNATURE_PORTS`/`AMBIGUOUS_PORTS` docstring) — corrected once Fix 4 ships, since it currently asserts a limitation this plan removes.
- `lab/auditor/worker/Dockerfile` / `docker-compose.yml` — only if the OUI registry fetch needs a new volume for its cache file (mirrors `grype-db-data`'s existing named-volume pattern) — confirm during Task 2 whether reusing the existing bind-mounted `document-store` volume is simpler than a new named volume.

---

## Task 1: Split the Telnet/SSH "ambiguous" confidence tier

**Why this order first:** smallest, lowest-risk, fully additive, no architecture change — ships and is live-verifiable independently of everything else.

- [x] In `_classify_host()` (`scan_tests.py:429`), replace the single `ambiguous_hits` branch with two cases:
  - Telnet present (23 in open_ports, regardless of whether 22 is also open) → `classification="uncertain"`, `confidence="medium"` (upgraded from `"low"`), rationale explicitly names Telnet as the driving signal and explains why it's a stronger legacy-IoT/appliance indicator than SSH.
  - SSH present without Telnet (22 in open_ports, 23 not) → `classification="uncertain"`, `confidence="low"` (unchanged), rationale explicitly says SSH alone is ubiquitous on non-IoT Linux/network gear and is *not* being weighted as an IoT signal.
- [x] Widen the frontend `confidence` union in `types.ts:142` to `"high" | "medium" | "low"`.
- [x] `NetworkDiscoveryPanel.tsx`: confidence wasn't rendered at all before this fix — added a small `ConfidenceLabel` next to the classification badge so the new medium/low distinction is actually visible; confirmed no TypeScript narrowing anywhere assumed only 2 values.
- [x] Tests (`test_scan_tests.py`): replaced `test_parse_network_discovery_classifies_telnet_only_host_as_uncertain_not_iot` with 3 cases — telnet-only (medium), ssh-only (low), telnet+ssh (medium) — keeping the existing "uncertain, not iot_device" assertion and adding the new confidence-tier + rationale-text assertions.
- [x] Updated `docs/known-limitations.md`'s "Telnet/SSH alone = uncertain" sentence to describe the two-tier distinction, including the honest SSH-only-not-live-verified caveat below.
- [x] Live-verified: real sweep (network scan #13) against the real lab confirmed `telnet-sim` (172.30.0.6, Telnet-only) now shows `confidence: "medium"` with the expected rationale text, and no other host's classification/confidence changed. **Noted honestly in the docs**: this lab has no real SSH-only host today, so the SSH-only/`"low"` branch is unit-test-verified only, not live-verified. Browser-based visual verification of the new `ConfidenceLabel` UI was not performed this session (Claude-in-Chrome extension not connected) — noted here rather than claimed.

## Task 2: Capture MAC address + a maintained OUI vendor lookup

- [x] Added a MAC-address regex to `_parse_network_discovery_observations()` (alongside the existing per-port regex, same per-host block scope): matches `^MAC Address: ([0-9A-Fa-f:]+) \((.+)\)$`, capturing nmap's own address + vendor guess per host block. "Unknown" is normalized to `None`, not surfaced as if it were a real vendor.
- [x] Built `lab/auditor/worker/scan_scripts/oui_lookup.py`, mirroring `cisa_kev.py`:
  - Fetches IEEE's public MA-L registry (`https://standards-oui.ieee.org/oui/oui.csv`) — **a real, live-confirmed finding during implementation**: the feed's own front-end 418s on the default `requests` User-Agent (a WAF bot-block, not an auth requirement), fixed with a fixed browser-shaped `User-Agent` header. Confirmed live: 39,889 real rows fetched.
  - Caches it locally by reusing the existing `grype-db-data` volume/cache directory (`~/.cache/grype/db/ieee-oui.csv`) — simpler than a new named volume, same class of small/infrequently-changing reference data KEV's own cache already lives alongside.
  - A staleness check on the same low-frequency cadence pattern as `maybe_refresh_grype_db`/`maybe_refresh_cisa_kev` in `job_runner.py` (new `maybe_refresh_oui_registry`).
  - `lookup_vendor(mac_address, index=None) -> str | None` — looks up the OUI (first 3 octets) against the cached registry; returns `None` (never a guess) if the cache is empty/stale-and-unreachable or the OUI genuinely isn't in the registry (e.g. a locally-administered/random MAC, which the registry correctly has no entry for — the honest, expected Docker-lab result).
- [x] In `job_runner.py`, wired `oui_lookup.py`'s refresh into the existing periodic-refresh poll pattern (`maybe_refresh_oui_registry()` alongside `maybe_refresh_grype_db`/`maybe_refresh_cisa_kev` in `main()`'s loop), plus a new `_enrich_mac_vendors()` helper (registry-first, nmap-bundled-fallback, never drops nmap's own answer) called from both `process_job()` and `process_network_scan()` after the pure parser returns — this is a live filesystem read, so it cannot live inside `scan_tests.py`'s pure functions.
- [x] Folded into observations: each host gets `mac_address`, `mac_vendor` (registry-first, nmap-bundled fallback), and `mac_vendor_source` (`"ieee_registry"` | `"nmap_bundled"` | `None`) — the honest provenance trail, matching `collector_versions`/`tool_version`'s existing pattern.
- [x] `types.ts`: added `mac_address`, `mac_vendor`, `mac_vendor_source` (`MacVendorSource | null`) to `DiscoveredHost`.
- [x] `NetworkDiscoveryPanel.tsx`: renders the MAC + vendor (with source) when present, with an honest inline note when vendor is unresolved explaining Docker's locally-administered MACs correctly have no registry entry.
- [x] Tests: 12 new `test_oui_lookup.py` cases (mocked HTTP fetch incl. the User-Agent regression, cache staleness, fallback path, unknown-OUI → `None`) + 3 new `test_scan_tests.py` parser cases using the real `EV-2026-07-23-0001.txt` MAC line text as fixture + 8 new `test_job_runner.py` cases (`maybe_refresh_oui_registry` sentinel behavior + `_enrich_mac_vendors` both code paths, mocked) + 2 new frontend tests.
- [x] Updated `docs/known-limitations.md`: replaced "Deliberately does not use MAC-vendor (OUI) lookup" with an accurate description of what's now captured, keeping the honest caveat that Docker's virtual MACs mean this lab will (correctly) show `null` for its own real device fleet.
- [x] Live-verified: restarted `auditor-worker` (bind-mounted code), confirmed the periodic refresh fetched the real 39,889-row registry into the shared cache volume on first loop iteration; ran a real sweep (network scan #14) and confirmed every real host's `mac_address` was captured with `mac_vendor`/`mac_vendor_source` honestly `null` (every lab MAC is locally-administered); directly confirmed both resolution paths work by calling `lookup_vendor()` in the live container against a real known OUI (`E8:0A:B9:...` → "Cisco Systems, Inc") and a real Docker virtual MAC (`E6:4D:1A:E6:45:D7` → `None`). **A real, unrelated test bug caught and fixed during this live pass**: `NetworkDiscoveryPanel.test.tsx` never wrapped the panel in a Router even though it renders a `<Link>` once its own unmocked `activeNetworkScopeCidrs()` fetch resolves — previously masked because that fetch always failed with no live API on the test host, but it started crashing the instant this session's live-verification stack came up on `localhost:8000` and the fetch started succeeding for real. Fixed with a `renderPanel()` helper wrapping every call in `MemoryRouter`, so the suite no longer depends on whether a live API happens to be reachable from the test host.

## Task 3: Fold SSDP (UPnP) and mDNS discovery into the primary sweep

- [ ] Append `--script broadcast-upnp-info,broadcast-dns-service-discovery` to Stage B's nmap command (see Task 4 — this lands after the two-stage split since Stage B is where a full script-capable scan belongs, not the fast Stage A ping sweep).
- [ ] **Before writing the parser**, capture real output shape by running this exact command live against this lab's real `device-router-gw` (UPnP) and `device-speaker` (mDNS) containers — do not guess the format from nmap's own doc text alone, matching this project's own standing discipline (the same discipline that caught the `X448MLKEM1024` and RTSP-methods-regex bugs in earlier phases). Broadcast-script results appear in nmap's own "Pre-scan script results:" block, not inside a per-target "Nmap scan report for X" block — write the regex against the real captured text.
- [ ] Parse each broadcast script's reported entries and, for each IP found:
  - If that IP already has a per-host block from the regular port scan (e.g. the two fixtures also expose HTTP on port 80, per `IOT_SIGNATURE_PORTS`'s own existing comment), fold the discovery signal into that host's existing `services`/observations entry (e.g. append `"upnp_broadcast"`/`"mdns_broadcast"` to a new `discovery_signals` list) rather than creating a duplicate host.
  - If the IP is genuinely new (a UDP-only device that never appeared in the TCP port-scan blocks at all — the real scenario this whole gap exists for), create a new host entry: `classification="iot_device"`, `confidence="high"`, rationale explicitly stating it responded to a UPnP/mDNS broadcast query, a signal restricted to devices that speak an IoT/consumer discovery protocol.
- [ ] Update the `IOT_SIGNATURE_PORTS`/`AMBIGUOUS_PORTS` docstring block (`scan_tests.py` ~lines 384-391) — it currently asserts "1900 (SSDP/UPnP) and 5353 (mDNS) are deliberately NOT added... a real, documented scope limit" — this becomes stale the moment this fix ships and must be rewritten to describe the new broadcast-script-based coverage.
- [ ] Tests: hand-author a fixture from the real captured output (previous bullet), covering both the fold-into-existing-host case and the new-UDP-only-host case; a regression test asserting the docstring's old claim ("TCP-only, can never see 1900/5353") no longer describes reality is optional but would be a nice, self-documenting guard.
- [ ] Update `docs/known-limitations.md`'s 1900/5353 caveat to match.
- [ ] Live-verify: real sweep against the real fleet; confirm `device-router-gw`/`device-speaker` now carry a `discovery_signals` entry, and (as a genuine regression check) confirm nothing about their existing HTTP-port-80-driven `iot_device` classification changed — both signals should agree, not conflict.

## Task 4: Two-phase discovery for subnet-size scalability

**This is the highest-risk task — it changes `job_runner.py`'s execution model for this one test.** Do it last, after Tasks 1–3 are shipped and live-verified independently, so a problem here doesn't block the lower-risk wins.

### Stage A — fast host discovery (whole configured scope, no ports)

- [ ] New pure function `_network_discovery_stage_a_command() -> list[str]`: `["nmap", "-sn", "--max-retries", "1", "--max-rate", "50", *ACTIVE_SCOPES]` — no `-sV`, no `-p`. For the audit-network's directly-attached L2 segment this is nmap's own ARP-based discovery (already proven live); for a routed/non-local configured scope nmap automatically falls back to ICMP/TCP ping probes — either way, dramatically cheaper per-address than a full version-detection scan.
- [ ] New pure function `_parse_stage_a_live_hosts(output: str) -> list[str]`: extract every live host's IP from `-sn`'s "Nmap scan report for ... (ip)" / "Host is up" blocks (reuse the same block-splitting approach `_parse_network_discovery_observations` already uses).
- [ ] New `estimate_stage_a_timeout(scopes: list[str]) -> int`: `STAGE_A_BASE_SECONDS + STAGE_A_PER_ADDRESS_SECONDS * total_usable_addresses(scopes)`, capped at `STAGE_A_MAX_SECONDS`. Pick conservative constants and **label them explicitly as an estimate this project has not live-measured beyond a /24** (this project's only real measurement is ~25s for a /24 doing a full `-sV` scan, not a ping-only scan — do not present the ping-only estimate as equally well-verified).
- [ ] If Stage A finds 0 live hosts: short-circuit, skip Stage B entirely, return an observations dict with 0 hosts and a clear note ("no live hosts responded across the configured scope(s) during the fast discovery pass") — this is a real, honest, valid outcome, not an error.

### Stage B — targeted service scan (only Stage A's live hosts)

- [ ] New pure function `_network_discovery_stage_b_command(live_hosts: list[str]) -> list[str]`: same shape as today's `_network_discovery_command` (`-sV --version-intensity 2 -p <ports> -T3 --max-retries 1 --max-rate 50`) plus Task 3's `--script broadcast-upnp-info,broadcast-dns-service-discovery`, but targeting the explicit `live_hosts` IP list instead of a CIDR.
- [ ] New `estimate_stage_b_timeout(live_host_count: int) -> int`: `STAGE_B_BASE_SECONDS + STAGE_B_PER_HOST_SECONDS * live_host_count`, capped at `STAGE_B_MAX_SECONDS`. Derive the per-host constant conservatively from the one real measurement this project has (~25s total for 9 live hosts out of a 256-address /24, most of that overhead being fixed nmap startup/reporting cost, not per-host cost) — again, label as an estimate.
- [ ] The existing `_parse_network_discovery_observations()` becomes Stage B's parser, unchanged in output shape (it already only reads whatever "Nmap scan report for X" blocks are present — feeding it a smaller, explicit target list instead of a CIDR requires no change to the parser itself).

### Orchestration

- [ ] New `job_runner.py` function `_run_network_discovery(patch_fn: Callable[[dict], None]) -> None` (or equivalent) that: runs Stage A with `estimate_stage_a_timeout()`, parses live hosts, runs Stage B (or short-circuits) with `estimate_stage_b_timeout()`, and calls the existing parser on Stage B's raw output. Both `process_job()`'s and `process_network_scan()`'s `TEST-NET-DISCOVERY`/`is_network_discovery_test()` branches call this one shared function instead of duplicating two-stage logic.
- [ ] Store Stage A's raw output too (as `stage_a_raw_output` or folded into the existing `raw_output` field with a clear separator) for audit-trail completeness — never discard it, matching this project's "raw output is always preserved" rule.
- [ ] Failure handling: a Stage A timeout/exception fails the whole scan (can't proceed without a live-host list) with a clear error distinguishing "discovery phase" from "service-scan phase" failures; a Stage B timeout/exception fails the scan the same way `process_network_scan`'s single-stage version does today, but the error message should say which stage failed.

### Tests & verification

- [ ] `test_scan_tests.py`: unit tests for `_network_discovery_stage_a_command`, `_parse_stage_a_live_hosts`, `_network_discovery_stage_b_command` (confirm it targets explicit IPs, not a CIDR, and carries the Task 3 script args), `estimate_stage_a_timeout`/`estimate_stage_b_timeout` (formula correctness + cap behavior at both small and very large configured scopes).
- [ ] `test_job_runner.py`: mock both `subprocess.run` calls, confirm the two-stage sequencing, the 0-live-host short-circuit, per-stage timeout values actually reaching `subprocess.run`, and that a Stage A failure never attempts Stage B.
- [ ] **Regression, not just new coverage**: live-verify that a real sweep of the existing audit-network /24 produces classification results equivalent to today's single-stage sweep (same hosts, same classifications, same MAC/vendor/broadcast data now on top) — this must not silently change existing behavior for the size this project has always run at.
- [ ] **Closest available large-scope proxy in this lab**: use the already-built Network Scope UI/API to add a real but currently-empty-of-devices larger private range (e.g. a /20 or /18 within an unused RFC1918 block) as a second active scope, and confirm Stage A's ping sweep actually completes within its estimated timeout and correctly reports 0 live hosts there — the closest real test this lab can offer for "a larger subnet" without provisioning new hosts. Explicitly document in `docs/known-limitations.md` that this proxy test does not fully validate Stage B's behavior at genuine large-live-host-count scale (this project has no way to spin up thousands of live hosts) — say so rather than imply full-scale validation happened.
- [ ] Update `docs/known-limitations.md`'s "Network discovery classification" section with the new two-stage architecture, its honest timeout-estimate caveat, and the proxy-test caveat above.

---

## Rollout Sequencing

Ship as 4 separate, independently live-verified commits, in the order above (matches this project's own established "one phase per commit, verify live before moving on" discipline):

1. Confidence-tier split — lowest risk, fully additive.
2. MAC + OUI capture — low risk, additive, new external fetch dependency but a well-precedented shape (`cisa_kev.py`).
3. Broadcast SSDP/mDNS fold-in — medium risk, needs a real live-capture step before the parser can be written correctly.
4. Two-phase scale redesign — highest risk, the only one touching `job_runner.py`'s execution model; do this last so a problem here doesn't block the other three, lower-risk wins from shipping.

After all 4 land: full regression (`policies/catalog`, `lab/auditor/api`, `lab/auditor/worker` in-container, frontend Vitest, `tsc -b`/`oxlint`), rebuild/redeploy `auditor-worker` (bind-mounted `policies/`+`lab/auditor/worker/`, likely no image rebuild needed unless the `Dockerfile`/`requirements.txt` changed for the OUI-cache volume), and a final end-to-end live pass against the real fleet. Update `CLAUDE.md` §0/§8 with the completed work, any real bug this catches (per this project's mandatory error-log convention, `docs/errors/`), and the final honest state of what is/isn't live-verified at scale.
