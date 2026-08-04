# Device vendor realism

**Illustrative simulation only.** Every device in this lab (`lab/devices/`)
is a small FastAPI app this project wrote from scratch. None of them run
real vendor firmware, real vendor source code, or a real vendor's binary in
any form. The vendor/model identity each device presents (HTTP banners,
Telnet/SSDP/UPnP/mDNS/Modbus responses, self-reported `/api/device/info`) is
chosen to match a real, market-relevant product so that this project's
findings and research report can cite a real, documented vulnerability
class instead of an invented one — the same technique established
ICS/IoT honeypot projects use (e.g. Conpot's default template identifies
itself as a real Siemens SIMATIC S7-200). **None of these devices are
affiliated with, endorsed by, or produced by the vendor named below.**

## Scope of the realism (2026-08-04)

What changed: vendor/model/firmware-version identity, plus protocol-level
signals that a real network scan would actually observe — Telnet banner,
SSDP `SERVER` header + UPnP `description.xml`, mDNS TXT record, RTSP
`Server:` header, Modbus device-identification (function code 0x2B).

What deliberately did **not** change: the existing generic REST JSON
endpoint paths (`/api/device/info`, `/api/config`, `/api/clips`, ...) are
not rewritten to mimic each real vendor's actual API shape (e.g.
Hikvision's ISAPI XML tree, Dahua's `/cgi-bin/magicBox.cgi` CGI
convention). This project's scan collectors (`policies/catalog/scan_tests.py`)
already parse generically by banner/port/protocol, not by URL path, so a
path-shape rewrite would add no new detection capability for a
materially larger effort — a deliberate, named limitation, not an
oversight.

`device_id`/container/service names (`device-insecure`, `device-router-gw`,
etc.), the scan-target security boundary (`device_validation.py`), and all
compliance/vulnerability classification logic are unchanged by this work —
confirmed vendor-agnostic before any of it was touched.

## Per-device mapping

| Fixture | Real analog | Grounding CVE(s) / rationale |
|---|---|---|
| `smart-camera` (insecure `device-insecure`, partial `device-partial`) | **Hikvision** DS-2CD21xx | CVE-2017-7921 — a backdoor account enabling privilege escalation on certain Hikvision camera models |
| `smart-camera` (hardened `device-hardened`) | **Axis Communications** M3216-LVE | Real-world "hardened by vendor culture" contrast — Axis is publicly known for signed firmware, HTTPS-only management, and a public vulnerability-disclosure program, not one specific CVE |
| `smart-lock` (`device-smartlock`) | **Yale** Conexis L1 | CVE-2023-26941 / CVE-2023-26942 — a remote PIN-verification bypass, published by Pen Test Partners |
| `plc-gateway` (`device-plc-gateway`) | **Schneider Electric** Modicon M221 | CVE-2024-11737 — unauthenticated command injection over Modbus TCP port 502, CVSS 9.8 |
| `router-gateway` (`device-router-gw`) | **Netgear** R7000 (Nighthawk family) | CVE-2021-34991 — unauthenticated RCE via the UPnP service, plus Netgear's long-documented default-credential history |
| `nvr` (`device-nvr`) | **Dahua** NVR4108-8P | CVE-2021-33045 — full NVR/DVR/XVR authentication bypass; CVE-2013-3612 — static root password over Telnet |
| `smart-speaker` (`device-speaker`) | **Sonos** One (Gen 2) | CVE-2018-11316 — unauthenticated UPnP access via DNS rebinding; CVE-2023-50809 — unauthenticated RCE enabling covert audio recording |

## Real IEEE OUI prefixes

Each fixture's self-reported `device_mac` (shown only via its own
`/api/device/info`, and in the manual Device Console) uses the real
vendor's IEEE-registered OUI prefix, verified against the public IEEE MA-L
registry at implementation time — never invented:

| Vendor | OUI prefix |
|---|---|
| Hikvision | A4:14:37 |
| Axis Communications | AC:CC:8E |
| Yale (ASSA ABLOY) | B0:44:9C |
| Schneider Electric | 9C:0E:51 |
| Netgear | E0:46:EE |
| Dahua | 14:A7:8B |
| Sonos | 38:42:0B |

**This is cosmetic, and documented as such deliberately.** The real
network-discovery OUI/vendor lookup
(`policies/catalog/oui_lookup.py`/`_enrich_mac_vendors` in
`lab/auditor/worker/job_runner.py`) only ever resolves the MAC nmap's own
ARP-based discovery reports — the real, Docker-assigned virtual MAC on each
container's network interface. It never reads a device's self-reported
`device_mac` field. Every one of this lab's real container MACs correctly
resolves to `null` against the IEEE registry (Docker's virtual MACs are
locally-administered and have no registry entry) — unchanged by this work,
same behavior CLAUDE.md already documents.

## A real, non-cosmetic addition: Modbus device identification — and what it doesn't close

`plc-gateway`'s reskin added real functionality, not just a rename: Modbus
function code 0x2B (Read Device Identification), via pymodbus's
`ModbusDeviceIdentification`, populated from the device's vendor/model/
firmware settings. Real Modicon PLCs answer this function code with no
authentication, matching the fixture's existing insecure-by-default Modbus
posture. **Confirmed live**, not just unit-tested: a direct pymodbus
client's `read_device_information()` call against the rebuilt container
correctly returned `{0: b"Schneider Electric", 1: b"Modicon M221", 2:
b"SV3.8.1"}`.

**This does not close the previously-documented `modbus-discover` "no
data" gap** — an initial claim to that effect, made before live-verifying
it, turned out to be wrong, corrected here rather than left standing.
Live verification (a hand-crafted raw Modbus/TCP frame against the
rebuilt container, cross-checked against a known-working `0x03` Read
Holding Registers call on the identical framing/socket to rule out a
framing bug) showed nmap's real `modbus-discover.nse` script never
reaches the 0x2B call at all: it first scans slave ids 1–246 with
function code `0x11` (Report Slave ID) and only calls `read_device_
information` as a follow-up once *that* gets a real response. pymodbus's
server does not answer function `0x11` at all (no response, no exception
PDU, confirmed with a 4-second wait) even though it correctly has a
built-in `ReportSlaveIdRequest` handler registered — the root cause inside
pymodbus's async server dispatch wasn't pursued further, since chasing it
is a materially different, unbounded task from a vendor-identity reskin.
The `modbus-discover` NSE script still returns no host script results
against this fixture, unchanged from before this pass.

## Known limitation: RTSP `Server:` header isn't wired into the collector

`nvr`'s RTSP responder now sends a `Server:` header and a vendor-flavored
SDP session name on every response — real signal for a direct RTSP client.
This is **not** currently parsed by this project's `TEST-RTSP-PROBE`
collector: that collector runs nmap's `rtsp-methods` NSE script, which
doesn't surface a `Server:` line in its own output at all (confirmed by
reading the script's actual behavior, not assumed). Extending this would
mean building a new probe mechanism — out of scope for a vendor-realism
pass, and named here rather than silently dropped.
