# Device Inventory

> Every vendor/model below is a real, market-relevant product used as an
> **illustrative simulation target** — not real vendor firmware, not
> affiliated with or endorsed by the named vendor. Full rationale and CVE
> citations: `docs/device-vendor-realism.md`.
>
> **2026-08-04 cutover note:** before this date, every device in this lab
> identified with a fully invented vendor (AcmeCam, BoltGuard, IndustraLink,
> NetCore, ViewKeep, VoxHome). `device_id`/container names, endpoint paths,
> and all classification/compliance logic are unchanged — only the
> vendor/model/firmware identity and protocol-level banners changed.
> Evidence recorded **before** this date (`document-store/raw/*.txt`) still
> shows the old fictional identity — that's an accurate point-in-time
> capture, not a bug; it is intentionally left as-is per this project's
> append-only evidence rule.

| device_id | vendor | model | mac | firmware |
|---|---|---|---|---|
| device-insecure | Hikvision | DS-2CD2143G2-I | A4:14:37:00:11:22 | V5.3.0 build 160530 |
| device-partial | Hikvision | DS-2CD2143G2-IU | A4:14:37:00:11:33 | V5.5.0 build 190723 |
| device-hardened | Axis Communications | M3216-LVE | AC:CC:8E:00:11:44 | AXIS OS 11.11.100 |
| device-smartlock | Yale | Conexis L1 | B0:44:9C:00:22:01 | 1.4.2 |
| device-plc-gateway | Schneider Electric | Modicon M221 | 9C:0E:51:00:22:02 | SV3.8.1 |
| device-router-gw | Netgear | R7000 | E0:46:EE:00:22:03 | V1.0.11.132_10.2.132 |
| device-nvr | Dahua | NVR4108-8P | 14:A7:8B:00:22:04 | 3.218.0000019.0 |
| device-speaker | Sonos | One (Gen 2) | 38:42:0B:00:22:05 | 15.9 |

Every `mac` above uses the real vendor's registered IEEE OUI prefix
(verified against the public IEEE MA-L registry) — self-reported only, via
each device's own `/api/device/info`. It is never consumed by the real
network-discovery OUI/vendor lookup (`policies/catalog/oui_lookup.py`),
which only ever resolves nmap's ARP-discovered, Docker-assigned virtual
MAC — this lab's real container MACs correctly resolve to `null` against
the IEEE registry, same as before this reskin.

Source of truth:
`lab/devices/smart-camera/profiles/{insecure,partial,hardened}.env` and
`lab/devices/{smart-lock,plc-gateway,router-gateway,nvr,smart-speaker}/profiles/insecure.env`.
