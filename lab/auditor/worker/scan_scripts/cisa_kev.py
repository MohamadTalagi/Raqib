"""Fetch and cache CISA's Known Exploited Vulnerabilities (KEV) catalog.

A single published JSON feed (no auth, ~1-2MB, confirmed live: 1656 entries
as of this writing), refreshed out of band on the same cadence as Grype's
vulnerability DB (see job_runner.py's maybe_refresh_cisa_kev) - never
fetched at scan time, matching the same hybrid model
TEST-FW-MANIFEST's Grype integration already uses. Kept independent of
Grype's own schema/version, since KEV listing isn't a first-class field in
Grype's JSON output at the pinned v0.82.0 (confirmed via a live spike).
"""

import json
import os
from pathlib import Path

import requests

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH = Path(
    os.environ.get("CISA_KEV_CACHE_PATH", os.path.expanduser("~/.cache/grype/db/cisa-kev.json")),
)
FETCH_TIMEOUT_SECONDS = 30


def fetch_and_cache_kev_feed() -> bool:
    """Downloads the real feed and atomically replaces the cache. Returns
    True on success, False (never raises) on any failure - callers keep
    using whatever was cached before, exactly like a failed `grype db
    update` leaves the last-good DB in place."""
    try:
        response = requests.get(KEV_FEED_URL, timeout=FETCH_TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return False
    if "vulnerabilities" not in data:
        return False

    KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = KEV_CACHE_PATH.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(data))
    tmp_path.replace(KEV_CACHE_PATH)  # atomic swap - never a half-written cache
    return True


def load_kev_index() -> dict:
    """cveID -> {"date_added": ..., "known_ransomware_use": ...}. Returns an
    empty dict (never raises) if no cache exists yet or it's unreadable -
    every caller already treats "not in the index" as "not KEV-listed",
    which is the honest answer when we simply don't have the data yet."""
    try:
        data = json.loads(KEV_CACHE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        v["cveID"]: {
            "date_added": v.get("dateAdded"),
            "known_ransomware_use": v.get("knownRansomwareCampaignUse"),
        }
        for v in data.get("vulnerabilities", [])
        if "cveID" in v
    }
