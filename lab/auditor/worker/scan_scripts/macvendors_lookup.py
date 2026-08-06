"""MAC address -> vendor resolution via the macvendors.com API, with a local
per-MAC cache and the existing IEEE registry as an offline fallback.

Why this exists alongside oui_lookup.py, rather than replacing it: they see
different MACs and answer slightly different questions. oui_lookup.py resolves
whatever MAC nmap ARP-discovers during a subnet sweep (inside this Docker lab
that is always a locally-administered virtual MAC, correctly unresolvable).
This module resolves the MAC a device *reports about itself* over HTTP - which
in this lab carries a real, registered vendor OUI - so it can be compared
against the vendor that same device claims in text. A device asserting one
vendor while carrying another's OUI is a real signal, and neither module could
produce it alone.

Resolution order, three tiers, mirroring the Grype -> static-table -> honest
"no data" discipline `_parse_fw_manifest_observations` already follows:

  1. the local per-MAC cache      (offline, instant, makes a re-run reproducible)
  2. the cached IEEE MA-L registry (offline, already maintained by job_runner)
  3. a live api.macvendors.com call (network, rate-limited, then cached)

and `None` if all three miss. Tier 3 is the only live call in the chain, and
it is deliberately last: a repeat scan of the same device answers entirely
from tier 1, so recorded evidence stays reproducible without a network
round-trip. That is a softer version of this project's "never fetch at scan
time" rule than the Grype/KEV/NVD feeds get, and it is defensible for exactly
one reason: an IEEE OUI assignment is effectively immutable, so a cached
answer does not go stale the way a vulnerability feed does.

Live-measured facts this module is built on (2026-08-06, real calls):
  - No API key is required. Every one of this lab's 8 fixture MACs resolved.
  - An unknown OUI returns a clean HTTP 404 (confirmed with a real Docker
    virtual MAC from this project's own committed evidence) - a definite
    "not registered", distinct from a failure, and cached as such.
  - The free tier is strictly ~1 request/second: a second immediate request
    returns HTTP 429 with a "Please slow down your requests" body. Hence
    REQUEST_INTERVAL_SECONDS and the single paced retry below.
"""

import json
import os
import time
from pathlib import Path

import requests

from lab.auditor.worker.scan_scripts import oui_lookup

MACVENDORS_API_URL = "https://api.macvendors.com"
MACVENDORS_CACHE_PATH = Path(
    os.environ.get(
        "MACVENDORS_CACHE_PATH",
        os.path.expanduser("~/.cache/grype/db/mac-vendors.json"),
    ),
)
FETCH_TIMEOUT_SECONDS = 10
# Free tier is ~1 req/s (measured - see the module docstring). A little
# headroom over 1.0s, overridable for a paid plan.
REQUEST_INTERVAL_SECONDS = float(os.environ.get("MACVENDORS_REQUEST_INTERVAL_SECONDS", "1.2"))

SOURCE_CACHE = "cache"
SOURCE_MACVENDORS = "macvendors"
SOURCE_IEEE_REGISTRY = "ieee-registry"

# Sentinel stored in the cache for an OUI the API definitively reported as
# unregistered (HTTP 404). Distinct from "we have never asked", so a known
# negative is never re-fetched on every scan.
_NOT_REGISTERED = ""

_last_request_monotonic: float | None = None


def normalize_mac(mac_address: str) -> str | None:
    """A MAC's first 3 octets (its OUI) as 6 uppercase hex chars, or None if
    the input isn't a usable MAC. Same normalization oui_lookup.lookup_vendor
    applies, so both tiers key the same way."""
    if not mac_address:
        return None
    oui = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()[:6]
    if len(oui) != 6 or not all(c in "0123456789ABCDEF" for c in oui):
        return None
    return oui


def _headers() -> dict:
    # macvendors.com's paid tiers use a bearer token. Never required - the
    # free tier served every request this lab makes.
    api_key = os.environ.get("MACVENDORS_API_KEY")
    return {"Authorization": f"Bearer {api_key}"} if api_key else {}


def load_cache() -> dict:
    """OUI -> vendor name (or "" for a confirmed-unregistered OUI). Empty dict
    (never raises) when no cache exists or it's unreadable."""
    try:
        data = json.loads(MACVENDORS_CACHE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    vendors = data.get("vendors")
    return vendors if isinstance(vendors, dict) else {}


def _save_cache(cache: dict) -> None:
    """Atomic swap, same as every other cache in this directory. Never raises -
    a cache that can't be written just means the next scan re-fetches."""
    try:
        MACVENDORS_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = MACVENDORS_CACHE_PATH.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps({"vendors": cache}))
        tmp_path.replace(MACVENDORS_CACHE_PATH)
    except OSError:
        pass


def _throttle() -> None:
    global _last_request_monotonic
    if _last_request_monotonic is not None:
        elapsed = time.monotonic() - _last_request_monotonic
        if elapsed < REQUEST_INTERVAL_SECONDS:
            time.sleep(REQUEST_INTERVAL_SECONDS - elapsed)
    _last_request_monotonic = time.monotonic()


def fetch_vendor(mac_address: str) -> tuple[str | None, str | None]:
    """One live api.macvendors.com call. Returns (vendor, error).

    (vendor, None)  a real registered vendor name
    (None,   None)  HTTP 404 - the OUI is definitively not registered
    (None,   str)   the lookup failed; the caller must not treat this as
                    "no vendor", only as "we could not find out"

    Never raises. Paced by REQUEST_INTERVAL_SECONDS, with exactly one retry on
    a 429 - the free tier's limiter resets in about a second, so one paced
    retry converts the common burst case into a success without turning a real
    outage into a retry storm."""
    oui = normalize_mac(mac_address)
    if oui is None:
        return None, f"not a usable MAC address: {mac_address!r}"

    for attempt in range(2):
        _throttle()
        try:
            response = requests.get(
                f"{MACVENDORS_API_URL}/{mac_address}",
                headers=_headers(),
                timeout=FETCH_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            return None, f"macvendors.com request failed: {exc}"

        if response.status_code == 200:
            vendor = (response.text or "").strip()
            return (vendor, None) if vendor else (None, "macvendors.com returned an empty body")
        if response.status_code == 404:
            return None, None  # definitively not registered
        if response.status_code == 429 and attempt == 0:
            time.sleep(REQUEST_INTERVAL_SECONDS)
            continue
        return None, f"macvendors.com returned HTTP {response.status_code}"

    return None, "macvendors.com rate limit not cleared after one retry"


def resolve_vendor(mac_address: str, *, allow_network: bool = True) -> dict:
    """The public entry point: resolve one MAC to a vendor through all three
    tiers, returning which tier answered.

    {"oui": "A41437", "vendor": "Hangzhou Hikvision...", "source": "macvendors",
     "error": None}

    `vendor: None` with `error: None` means a real, checked "this OUI is not
    registered to anyone" - not the same as `error` being set, which means the
    lookup itself could not be completed. Keeping those apart is the whole
    reason this returns a dict rather than a bare string.

    `allow_network=False` restricts it to the two offline tiers, for a caller
    that must not make a network call."""
    oui = normalize_mac(mac_address)
    if oui is None:
        return {"oui": None, "vendor": None, "source": None,
                "error": f"not a usable MAC address: {mac_address!r}"}

    cache = load_cache()
    if oui in cache:
        cached = cache[oui]
        return {"oui": oui, "vendor": cached or None, "source": SOURCE_CACHE, "error": None}

    registry_vendor = oui_lookup.lookup_vendor(mac_address)
    if registry_vendor:
        return {"oui": oui, "vendor": registry_vendor, "source": SOURCE_IEEE_REGISTRY, "error": None}

    if not allow_network:
        return {"oui": oui, "vendor": None, "source": None,
                "error": "no offline source resolved this OUI and network lookup was disabled"}

    vendor, error = fetch_vendor(mac_address)
    if error is not None:
        return {"oui": oui, "vendor": None, "source": None, "error": error}

    # Cache both a hit and a confirmed 404, so a known-unregistered OUI is
    # never re-fetched on every subsequent scan.
    cache[oui] = vendor or _NOT_REGISTERED
    _save_cache(cache)
    return {"oui": oui, "vendor": vendor, "source": SOURCE_MACVENDORS, "error": None}
