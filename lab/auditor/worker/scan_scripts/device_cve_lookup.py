"""TEST-DEVICE-CVE-LOOKUP's collector: device-level CVE matching with no
firmware image required.

The premise this exists to serve: an auditor assessing a device they have
never held has its network presence, not its firmware binary. So instead of
unpacking an image, this matches the device's already-known vendor + model
against real NVD CVE data by CPE - the same technique Shodan/Vulners/
cve-search use.

Shape notes, all of them deliberate and all of them matching an existing
convention in this codebase rather than inventing one:

  * No live host/port target (like TEST-FW-MANIFEST), and no uploaded
    archive either (unlike TEST-FW-MANIFEST) - only a device_id. See
    scan_tests.is_device_intel_test().
  * The worker has no direct database access (job_runner.py:93-95), so the
    device's vendor/model are read back from auditor-api's existing
    GET /devices/{id} - the same AUDITOR_API_URL callback precedent
    interface_detect.py already uses.
  * It NEVER calls NVD itself. The live fetch happens only in
    job_runner.py's scheduled maybe_refresh_device_cve_index(); this reads
    the local cache (nvd_lookup.load_device_advisories_index()). That is
    what keeps a recorded scan reproducible.

Prints `field=value` lines for scan_tests._parse_device_cve_lookup_
observations to read back, the same stdout contract every other Python
collector in this directory uses.
"""

import json
import os
import sys

import requests

from lab.auditor.worker.scan_scripts import nvd_lookup
from policies.catalog.scan_tests import lookup_device_cpe

API_URL = os.environ.get("AUDITOR_API_URL", "http://auditor-api:8000")
DEVICE_FETCH_TIMEOUT_SECONDS = 10


def main() -> None:
    if len(sys.argv) < 2:
        print("error=no device_id supplied")
        sys.exit(1)
    device_id = sys.argv[1]

    try:
        response = requests.get(
            f"{API_URL}/devices/{device_id}", timeout=DEVICE_FETCH_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        device = (response.json() or {}).get("device") or {}
    except (requests.RequestException, ValueError) as exc:
        # A real execution failure: job_runner turns a non-zero exit into
        # record-failure -> INCONCLUSIVE evidence, never a fabricated "no
        # CVEs found".
        print(f"error=could not fetch device record: {exc}")
        sys.exit(1)

    vendor = device.get("vendor")
    model = device.get("model")
    print(f"vendor={vendor or ''}")
    print(f"model={model or ''}")
    print(f"firmware_version={device.get('firmware_version') or ''}")

    cpe_prefix = lookup_device_cpe(vendor, model)
    print(f"cpe_matched={cpe_prefix is not None}")
    print(f"cpe={cpe_prefix or ''}")

    if cpe_prefix is None:
        # An honest miss, not an error: this product simply has no verified
        # CPE mapping. The parser renders it as such.
        return

    index = nvd_lookup.load_device_advisories_index()
    # Distinguishing "the cache has not been populated yet" from "this
    # product genuinely has zero published CVEs" matters - the second is a
    # real result, the first is missing data, and reporting them the same way
    # would be the exact overclaim this project forbids.
    print(f"index_available={cpe_prefix in index}")
    print(f"device_cves={json.dumps(index.get(cpe_prefix, []))}")


if __name__ == "__main__":
    main()
