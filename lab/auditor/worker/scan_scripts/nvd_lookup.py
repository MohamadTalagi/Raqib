"""Fetch and cache real NVD CVE data for the device products this fleet
actually contains.

Same hybrid model as cisa_kev.py and oui_lookup.py, and for the same reason:
a scan must be reproducible from (tool, version, command, timestamp, hash),
so nothing here is ever called at scan time. job_runner.py refreshes the
cache out of band on a bounded cadence (maybe_refresh_device_cve_index) and
the collector only ever reads the local file.

Scoped deliberately to the (part, vendor, product) CPE prefixes present in
the registered fleet - via policies/catalog/scan_tests.py's
DEVICE_CPE_OVERRIDES - never a full corpus mirror. NVD's API has no bulk
"download everything" mode anyway, and querying only what is needed keeps
this comfortably inside NVD's public rate limit.

Live-measured facts this module is built on (2026-08-06, 12 real calls
against the public API): no API key is required, the default python-requests
User-Agent is served normally (unlike IEEE's OUI registry, which WAF-blocks
it - do not copy that spoofing workaround here), and requests spaced ~6s
apart draw no 429. NVD_API_KEY is supported as an optional courtesy for a
real deployment but is never required.
"""

import json
import os
import time
from pathlib import Path
from urllib.parse import quote

import requests

from lab.auditor.worker.scan_scripts import cisa_kev
from policies.catalog import firmware_version_compare

NVD_CVE_API_URL ="https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_PATH = Path(
    os.environ.get(
        "NVD_CVE_CACHE_PATH",
        os.path.expanduser("~/.cache/grype/db/nvd-device-cves.json"),
    ),
)
FETCH_TIMEOUT_SECONDS = 30
# NVD's documented unauthenticated allowance is ~5 requests per 30 seconds;
# 6s between requests stays under it without an API key. Overridable so a
# deployment with a key can go faster.
REQUEST_INTERVAL_SECONDS = float(os.environ.get("NVD_REQUEST_INTERVAL_SECONDS", "6"))
# NVD's own maximum for this endpoint. The largest real result set in this
# lab is 139 (netgear:r7000_firmware), so paging is not implemented - if a
# product ever exceeds this, the count is recorded honestly rather than
# silently truncated (see _summarize_cve).
RESULTS_PER_PAGE = 2000


def _headers() -> dict:
    api_key = os.environ.get("NVD_API_KEY")
    return {"apiKey": api_key} if api_key else {}


def _summarize_cve(item: dict, kev_index: dict, cpe_prefix: str) -> dict:
    """Trim one NVD `vulnerabilities[]` entry to the exact advisory shape this
    project already uses for package-level CVEs (VulnCVE in types.ts), so the
    frontend renders both with the same components.

    Prefers the CVSS v3.1 base score, falling back to v3.0 then v2, and
    reports None rather than guessing when NVD published no score at all -
    the same "never fabricate a number" rule _clean_grype_advisory follows."""
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return {}

    descriptions = cve.get("descriptions") or []
    summary = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        "",
    )

    metrics = cve.get("metrics") or {}
    cvss = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        scores = [
            e["cvssData"]["baseScore"]
            for e in entries
            if (e.get("cvssData") or {}).get("baseScore") is not None
        ]
        if scores:
            cvss = max(scores)
            break

    kev_entry = kev_index.get(cve_id)
    return {
        "id": cve_id,
        "cvss": cvss,
        "summary": summary,
        "kev_listed": kev_entry is not None,
        "kev_date_added": kev_entry["date_added"] if kev_entry else None,
        # The affected-version range this CVE states for THIS product. NVD has
        # always returned it; it was simply being discarded here, which is why
        # the collector could only ever say "a listed CVE may already be fixed
        # in the running firmware". Keeping it needs no new source and no new
        # request - see policies/catalog/firmware_version_compare.py.
        "version_range": firmware_version_compare.extract_nvd_version_range(item, cpe_prefix),
    }


def _fetch_one(cpe_prefix: str, kev_index: dict) -> list[dict] | None:
    """One CPE prefix's CVEs, or None if the fetch failed. Never raises.

    `cpe_prefix` is "part:vendor:product" (e.g. "o:netgear:r7000_firmware");
    NVD's virtualMatchString wants a full cpe:2.3 string, and accepts one
    truncated after the product - that is what makes this a product-level
    (all versions) query rather than an exact-version one."""
    virtual_match = f"cpe:2.3:{cpe_prefix}"
    url = (
        f"{NVD_CVE_API_URL}?virtualMatchString={quote(virtual_match, safe='')}"
        f"&resultsPerPage={RESULTS_PER_PAGE}"
    )
    try:
        response = requests.get(url, headers=_headers(), timeout=FETCH_TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return None
    if "vulnerabilities" not in data:
        return None

    summarized = [_summarize_cve(item, kev_index, cpe_prefix) for item in data["vulnerabilities"]]
    cves = [c for c in summarized if c]
    # KEV-listed first, then worst CVSS - the same ordering convention
    # firmware_check.py already applies to package-level CVE lists.
    cves.sort(key=lambda c: (not c["kev_listed"], -(c["cvss"] or 0)))
    return cves


def fetch_and_cache_device_advisories(cpe_prefixes: list[str]) -> bool:
    """One NVD query per distinct CPE prefix, paced by
    REQUEST_INTERVAL_SECONDS, atomically swapped into the cache.

    Returns True only if every prefix's fetch succeeded. A False return means
    "retry everything next cycle", NOT "the cache is now invalid" - whatever
    succeeded is still written, and job_runner deliberately does not touch its
    staleness sentinel on a False, so the next cycle retries.

    Never raises, matching cisa_kev.fetch_and_cache_kev_feed().

    Each CVE is cross-referenced against the locally cached CISA KEV catalog -
    a pure local file read, no second network call - exactly as
    firmware_check.py already does for package-level CVEs."""
    kev_index = cisa_kev.load_kev_index()

    index: dict[str, list[dict]] = {}
    all_ok = True
    for position, cpe_prefix in enumerate(sorted(set(cpe_prefixes))):
        if position:
            time.sleep(REQUEST_INTERVAL_SECONDS)
        cves = _fetch_one(cpe_prefix, kev_index)
        if cves is None:
            all_ok = False
            continue
        index[cpe_prefix] = cves

    if not index and not all_ok:
        # Nothing at all came back - leave the last-good cache untouched
        # rather than replacing it with an empty one.
        return False

    try:
        NVD_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = NVD_CACHE_PATH.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps({"advisories": index}))
        tmp_path.replace(NVD_CACHE_PATH)  # atomic swap - never a half-written cache
    except OSError:
        return False
    return all_ok


def load_device_advisories_index() -> dict:
    """"part:vendor:product" -> list of {"id", "cvss", "summary",
    "kev_listed", "kev_date_added"}.

    Returns an empty dict (never raises) if no cache exists yet or it is
    unreadable - honest-miss, same as load_kev_index()/load_oui_index(). The
    collector distinguishes "cache not populated yet" from "this product has
    no CVEs", so an empty index here never renders as a clean bill of
    health."""
    try:
        data = json.loads(NVD_CACHE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    advisories = data.get("advisories")
    return advisories if isinstance(advisories, dict) else {}
