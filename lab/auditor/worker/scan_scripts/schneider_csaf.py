"""Fetch and cache Schneider Electric's real CSAF security advisories for the
Modicon M221 - this lab's only Schneider fixture, and the only one of its
seven branded vendors that publishes machine-readable advisories at all.

Same hybrid model as cisa_kev.py / oui_lookup.py / nvd_lookup.py: never
fetched at scan time, refreshed out of band by job_runner.py on a bounded
cadence, read from the local cache by the collector. That is what keeps a
recorded scan reproducible.

Advisory IDs are a small HAND-VERIFIED table, mirroring
DEVICE_CPE_OVERRIDES's own discipline - an ID goes in only after being
individually fetched and confirmed. This is not pedantry: two
plausible-looking guessed IDs were tried during implementation and resolved
to completely unrelated products (OSIsoft PI System, Ruijie Reyee OS). A
guessed advisory ID does not fail loudly, it silently attributes another
vendor's vulnerabilities to this device.

Scope, measured rather than assumed and worth stating plainly: this covers
ONE advisory, ONE CVE, ONE device. CVE-2024-11737 - the other Modicon M221
CVE this project cites in docs/device-vendor-realism.md - has exactly one
reference in NVD, a Schneider PDF, with no CSAF/ICSA JSON anywhere in CISA's
mirror. So NVD's own version ranges remain the primary source for every
device including this one; CSAF is a second, more authoritative opinion on
the single CVE it covers.
"""

import json
import os
import re
from pathlib import Path

import requests

from policies.catalog import firmware_version_compare

SCHNEIDER_M221_CPE_PREFIX = "o:schneider-electric:modicon_m221_firmware"

# CONFIRMED LIVE 2026-08-10 against CISA's public cisagov/CSAF mirror:
# .../csaf_files/OT/white/2018/icsa-18-240-02.json - title "Schneider Electric
# Modicon M221", CVE-2018-7789, product_version_range "<1.6.2.0".
SCHNEIDER_M221_CSAF_ADVISORY_IDS = ["ICSA-18-240-02"]

CSAF_MIRROR_BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white"
SCHNEIDER_CSAF_CACHE_PATH = Path(
    os.environ.get(
        "SCHNEIDER_CSAF_CACHE_PATH",
        os.path.expanduser("~/.cache/grype/db/schneider-csaf.json"),
    ),
)
FETCH_TIMEOUT_SECONDS = 30

_ADVISORY_ID_RE = re.compile(r"^ICSA-(\d{2})-\d{3}-\d{2}$", re.IGNORECASE)


def advisory_json_url(advisory_id: str) -> str | None:
    """The mirror URL for an advisory ID, or None if the ID isn't the shape
    this derivation was verified against.

    ICSA IDs embed their own year ("ICSA-18-240-02" -> 2018). Confirmed
    against advisories from three different years during implementation.
    Returning None for an unrecognized shape is deliberate: a wrong URL
    would 404 loudly, but a *plausible* wrong URL could return a real
    advisory for a different product entirely.
    """
    match = _ADVISORY_ID_RE.match((advisory_id or "").strip())
    if not match:
        return None
    year = f"20{match.group(1)}"
    return f"{CSAF_MIRROR_BASE}/{year}/{advisory_id.strip().lower()}.json"


def fetch_and_cache_schneider_csaf() -> bool:
    """Fetches every advisory in the table, merges their CVE -> version-range
    mappings, and atomically swaps the result into the cache.

    Returns True only if every advisory fetched and parsed. Partial success
    still writes what worked - mirroring
    nvd_lookup.fetch_and_cache_device_advisories - so one unreachable
    advisory never discards the others. Never raises.
    """
    ranges: dict[str, dict] = {}
    all_ok = True

    for advisory_id in SCHNEIDER_M221_CSAF_ADVISORY_IDS:
        url = advisory_json_url(advisory_id)
        if url is None:
            all_ok = False
            continue
        try:
            response = requests.get(url, timeout=FETCH_TIMEOUT_SECONDS)
            response.raise_for_status()
            advisory = response.json()
        except (requests.RequestException, ValueError):
            all_ok = False
            continue

        extracted = firmware_version_compare.extract_csaf_version_ranges(advisory)
        if not extracted:
            # Fetched fine but said nothing usable - a real outcome, not an
            # error, but it should not silently look like success either.
            all_ok = False
            continue
        ranges.update(extracted)

    if not ranges and not all_ok:
        # Nothing usable came back; leave the last-good cache untouched.
        return False

    try:
        SCHNEIDER_CSAF_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = SCHNEIDER_CSAF_CACHE_PATH.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps({"cve_version_ranges": ranges}))
        tmp_path.replace(SCHNEIDER_CSAF_CACHE_PATH)  # atomic swap
    except OSError:
        return False
    return all_ok


def load_schneider_csaf_index() -> dict:
    """{"cve_version_ranges": {cve_id: range_dict}}.

    Empty mapping (never raises) on a missing or corrupt cache - the same
    honest-miss convention every sibling module here follows.
    """
    try:
        data = json.loads(SCHNEIDER_CSAF_CACHE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {"cve_version_ranges": {}}
    ranges = data.get("cve_version_ranges")
    return {"cve_version_ranges": ranges if isinstance(ranges, dict) else {}}
