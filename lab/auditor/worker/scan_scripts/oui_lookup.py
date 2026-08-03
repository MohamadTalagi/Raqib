"""Fetch and cache the IEEE public MA-L (OUI) registry for MAC-vendor lookup.

Same hybrid model, same fetch/cache/staleness shape as cisa_kev.py: a single
published CSV feed (no auth), refreshed out of band by job_runner.py on a
low-frequency cadence, never fetched at scan time. Reuses the existing
grype-db-data volume/cache directory rather than provisioning a new one -
this is a small (~4MB), infrequently-changing reference table, the same
class of data KEV's own cache already lives alongside.

A real, live-confirmed finding while building this (worth recording, matching
this project's "verify before designing" discipline): the IEEE registry's own
front-end rejects a request carrying Python's default `requests` User-Agent
(`python-requests/x.x`) with an HTTP 418 "Request Rejected" from what looks
like a WAF - a plain browser-shaped User-Agent header is required. This has
nothing to do with authentication (the feed itself needs none); it is
purely a bot-blocking front-end policy, so a fixed, honest User-Agent string
is sent rather than working around it more deceptively.
"""

import csv
import io
import os
from pathlib import Path

import requests

OUI_FEED_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_CACHE_PATH = Path(
    os.environ.get("OUI_CACHE_PATH", os.path.expanduser("~/.cache/grype/db/ieee-oui.csv")),
)
FETCH_TIMEOUT_SECONDS = 30
# See the module docstring - the feed's own front-end 418s on the default
# `requests` User-Agent string.
FETCH_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; IoTGuard-OUI-Lookup/1.0)"}


def fetch_and_cache_oui_registry() -> bool:
    """Downloads the real IEEE MA-L registry CSV and atomically replaces the
    cache. Returns True on success, False (never raises) on any failure -
    callers keep using whatever was cached before, exactly like
    cisa_kev.fetch_and_cache_kev_feed."""
    try:
        response = requests.get(OUI_FEED_URL, timeout=FETCH_TIMEOUT_SECONDS, headers=FETCH_HEADERS)
        response.raise_for_status()
        text = response.text
    except requests.RequestException:
        return False
    if not text or "Registry" not in text.splitlines()[0]:
        return False

    OUI_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = OUI_CACHE_PATH.with_suffix(".csv.tmp")
    tmp_path.write_text(text, encoding="utf-8")
    tmp_path.replace(OUI_CACHE_PATH)  # atomic swap - never a half-written cache
    return True


def load_oui_index() -> dict:
    """OUI (6 uppercase hex chars, no separators) -> organization name.
    Returns an empty dict (never raises) if no cache exists yet or it's
    unreadable/malformed - every caller already treats "not in the index" as
    "vendor unresolved", the honest answer when we simply don't have the
    data yet."""
    try:
        text = OUI_CACHE_PATH.read_text(encoding="utf-8")
    except OSError:
        return {}
    index: dict[str, str] = {}
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            oui = (row.get("Assignment") or "").strip().upper()
            org = (row.get("Organization Name") or "").strip()
            if oui and org:
                index[oui] = org
    except csv.Error:
        return {}
    return index


def lookup_vendor(mac_address: str, index: dict | None = None) -> str | None:
    """Resolves a MAC address's first 3 octets (its OUI) against the cached
    IEEE registry. Returns None (never a guess) when the cache is
    empty/unreadable or the OUI genuinely has no registry entry - a
    locally-administered MAC (Docker's own container MACs, e.g. anything
    with the second-least-significant bit of the first octet set) correctly
    has no entry, which is the honest, expected result inside this lab, not
    a bug to paper over."""
    oui = mac_address.replace(":", "").replace("-", "").upper()[:6]
    if len(oui) != 6:
        return None
    if index is None:
        index = load_oui_index()
    return index.get(oui)
