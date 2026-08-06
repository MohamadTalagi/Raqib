"""TEST-DEVICE-MAC-VENDOR's collector: auto-extract a device's MAC address and
identify the vendor that OUI is registered to.

Two steps, no manual input at any point - the auditor picks a device and runs
the scan:

  1. Read the device's own unauthenticated GET /api/device/info and pull its
     `mac` field out. Same endpoint TEST-DEVICE-ID reads, deliberately: a
     dedicated scan that depends on another scan having run first would be a
     worse experience than one that just re-reads a cheap endpoint.
  2. Resolve that MAC's OUI to a vendor via macvendors_lookup (local cache ->
     cached IEEE MA-L registry -> live api.macvendors.com).

The result worth having is not just the vendor name, it is the COMPARISON:
this prints both the vendor the device claims in text and the vendor its MAC
prefix is actually registered to. A device asserting one while carrying the
other's OUI is a real signal - a spoofed or relabelled device, or simply a
mislabelled asset inventory. Neither the claimed string nor the OUI can show
that alone.

Prints `field=value` lines for scan_tests._parse_mac_vendor_observations to
read back, the same stdout contract every other Python collector here uses.
Exits non-zero only on a genuine execution failure (device unreachable), which
job_runner turns into record-failure -> INCONCLUSIVE evidence rather than a
fabricated result.
"""

import sys

import requests

from lab.auditor.worker.scan_scripts import macvendors_lookup

DEVICE_FETCH_TIMEOUT_SECONDS = 10


def main() -> None:
    if len(sys.argv) < 2:
        print("error=no device URL supplied")
        sys.exit(1)
    base_url = sys.argv[1].rstrip("/")

    try:
        # verify=False: this lab's HTTPS fixtures use self-signed certs, the
        # same allowance every other HTTPS collector here makes (curl -k).
        response = requests.get(
            f"{base_url}/api/device/info",
            timeout=DEVICE_FETCH_TIMEOUT_SECONDS,
            verify=False,
        )
        response.raise_for_status()
        info = response.json() or {}
    except (requests.RequestException, ValueError) as exc:
        print(f"error=could not read the device info endpoint: {exc}")
        sys.exit(1)

    mac = (info.get("mac") or "").strip()
    claimed_vendor = (info.get("vendor") or "").strip()
    print(f"mac={mac}")
    print(f"claimed_vendor={claimed_vendor}")

    if not mac:
        # A real, valid outcome: the device disclosed no MAC to extract. Not an
        # execution failure, so this exits 0 and the parser reports it.
        print("mac_disclosed=False")
        return
    print("mac_disclosed=True")

    result = macvendors_lookup.resolve_vendor(mac)
    print(f"oui={result['oui'] or ''}")
    print(f"oui_vendor={result['vendor'] or ''}")
    print(f"oui_source={result['source'] or ''}")
    print(f"lookup_error={result['error'] or ''}")


if __name__ == "__main__":
    main()
