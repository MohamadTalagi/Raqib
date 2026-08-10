"""Compares a device's self-reported firmware version against a version range
taken from an NVD CVE record or a Schneider Electric CSAF advisory.

Pure logic: no I/O, no network, no dependency on nvd_lookup/schneider_csaf, so
it is fully unit-testable in isolation - the same shape vuln_reference.py and
pqc_crypto_reference.py already established for reference/comparison modules.

Hand-rolled rather than using `packaging`: that library is importable inside
the worker container only as a transitive dependency and is pinned in neither
requirements.txt, so depending on it would be fragile. Every sibling module
here (cisa_kev.py, oui_lookup.py) is likewise dependency-free.

Two things about real-world firmware strings drive the design, both measured
rather than assumed (see handoff.txt section 9):

  * No real string in this lab is a clean dotted integer. They carry vendor
    prefixes and trailing suffixes - "V1.0.11.132_10.2.132", "SV3.8.1",
    "V5.3.0 build 160530", "AXIS OS 11.11.100". So the comparator extracts
    the leading dotted-numeric core and discards the rest.
  * NVD's own boundary values do the same ("versionEndIncluding":
    "1.0.7.2_1.1.93"), so that simplification applies to BOTH sides of a
    comparison, not just the device's string.

Discarding a suffix is a real loss of precision, disclosed in
docs/vulnerability-intelligence.md rather than hidden. It is the right
trade: comparing "1.0.11.132" against "1.0.11.136" answers the actual
question, while refusing to compare anything with a suffix would make the
feature useless for almost this entire fleet.
"""

import re

# A leading alphabetic vendor marker: "V1.0.0", "SV3.8.1", "AXIS OS 11.11.100".
# Deliberately allows spaces between the marker and the number - an earlier
# draft required the letters to sit immediately against the digit, which
# silently returned None for Axis's real "AXIS OS 11.11.100".
_LEADING_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z ]*(?=\d)")
# The first dotted-numeric run anywhere in what remains.
_NUMERIC_CORE_RE = re.compile(r"\d+(?:\.\d+)+")
# A single trailing revision letter, e.g. "1.2.3a" -> treated as 1.2.3.1.
_TRAILING_LETTER_RE = re.compile(r"^([a-zA-Z])(?![a-zA-Z0-9])")

# Statuses a single CVE can carry.
STATUS_AFFECTED = "affected"
STATUS_NOT_AFFECTED = "not_affected"
STATUS_AFFECTED_NO_FIX = "affected_no_fix"
STATUS_UNKNOWN = "unknown"

# Fleet-level rollup statuses.
CURRENCY_OUTDATED = "outdated"
CURRENCY_AFFECTED_NO_FIX = "affected_no_fix"
CURRENCY_CURRENT = "current"
CURRENCY_UNKNOWN = "unknown"

_NVD_BOUND_KEYS = (
    "versionStartIncluding", "versionStartExcluding",
    "versionEndIncluding", "versionEndExcluding",
)


def parse_version(raw: str | None) -> tuple[int, ...] | None:
    """The comparable numeric core of a firmware string, or None.

    None is always "could not determine", never a guess - a caller must treat
    it as unknown rather than falling back to string comparison. Returns None
    for a bare build number with no dot (e.g. "210628"), which carries no
    reliable ordering against a dotted version.
    """
    if not raw:
        return None
    text = _LEADING_PREFIX_RE.sub("", str(raw).strip())
    match = _NUMERIC_CORE_RE.search(text)
    if not match:
        return None
    core = tuple(int(part) for part in match.group(0).split("."))
    letter_match = _TRAILING_LETTER_RE.match(text[match.end():])
    if letter_match:
        return core + (ord(letter_match.group(1).lower()) - ord("a") + 1,)
    return core


def _padded(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple, tuple]:
    """Zero-pads the shorter tuple so 1.4 and 1.4.0 compare equal."""
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def _empty_range() -> dict:
    return {
        "start_including": None, "start_excluding": None,
        "end_including": None, "end_excluding": None, "unbounded": False,
    }


def _cpe_matches_for(item: dict, cpe_prefix: str) -> list[dict]:
    """Every cpeMatch entry in an NVD record belonging to this exact CPE.

    Two real properties of NVD's shape make the filtering non-optional:
    a single CVE record can list dozens of unrelated products from the same
    vendor (CVE-2021-34991 lists ~40 Netgear models), and `vulnerable: false`
    entries are the paired hardware CPE of an AND-node - never a statement
    that some range is safe. Both are dropped here.

    Recurses into nested `nodes` because NVD really does nest AND/OR groups.
    """
    found: list[dict] = []

    def walk(nodes) -> None:
        for node in nodes or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") or ""
                if match.get("vulnerable") and criteria.startswith(f"cpe:2.3:{cpe_prefix}:"):
                    found.append(match)
            walk(node.get("nodes"))

    for configuration in (item.get("cve") or {}).get("configurations") or []:
        walk(configuration.get("nodes"))
    return found


def extract_nvd_version_range(item: dict, cpe_prefix: str) -> dict | None:
    """The version range an NVD CVE record states for one specific CPE.

    Returns None when this CVE says nothing about this CPE at all - which is
    the normal, permanent result for a hardware-only (`h:`) CPE like Axis
    M3216-LVE, whose every match is the non-vulnerable partner of an AND-node.

    `unbounded: True` is NVD's real and common "every version of this product
    is listed as vulnerable" shape (no version keys present at all). It is a
    definite assertion, deliberately kept distinct from None - conflating
    "affects everything" with "we don't know" would lose a real finding.
    """
    matches = _cpe_matches_for(item, cpe_prefix)
    if not matches:
        return None

    ranges = []
    for match in matches:
        if not any(key in match for key in _NVD_BOUND_KEYS):
            ranges.append({**_empty_range(), "unbounded": True})
            continue
        ranges.append({
            "start_including": match.get("versionStartIncluding"),
            "start_excluding": match.get("versionStartExcluding"),
            "end_including": match.get("versionEndIncluding"),
            "end_excluding": match.get("versionEndExcluding"),
            "unbounded": False,
        })

    bounded = [r for r in ranges if not r["unbounded"]]
    if not bounded:
        return ranges[0]  # all unbounded - they agree by definition
    first = bounded[0]
    if any(other != first for other in bounded[1:]):
        # Several disagreeing ranges for one CPE. Picking one arbitrarily
        # would be a guess presented as a fact.
        return {"ambiguous": True}
    return first


_CSAF_OPERATORS = (
    ("<=", "end_including"),
    (">=", "start_including"),
    ("<", "end_excluding"),
    (">", "start_excluding"),
    ("=", "exact"),
)


def parse_csaf_range_expression(expression: str | None) -> dict | None:
    """CSAF states a range as a comparison expression string ("<1.6.2.0"),
    not as fielded keys like NVD. Normalized into the same shape so exactly
    one comparator serves both sources. Returns None on anything unrecognized
    rather than guessing at an operator."""
    if not expression:
        return None
    text = str(expression).strip()
    for token, field in _CSAF_OPERATORS:
        if text.startswith(token):
            value = text[len(token):].strip()
            if not value:
                return None
            if field == "exact":
                return {**_empty_range(), "start_including": value, "end_including": value}
            return {**_empty_range(), field: value}
    # A bare version with no operator means exactly that version.
    if _NUMERIC_CORE_RE.search(text):
        return {**_empty_range(), "start_including": text, "end_including": text}
    return None


def extract_csaf_version_ranges(advisory_json: dict) -> dict[str, dict]:
    """{cve_id: range} for one CSAF advisory.

    product_tree branches with category "product_version_range" carry the
    expression under "name", keyed by their product's product_id;
    vulnerabilities[] then maps each CVE to the product_ids it affects via
    product_status.known_affected[]. Never raises on a malformed advisory -
    an unparseable branch is skipped, matching every sibling module's
    honest-miss convention.
    """
    ranges_by_product: dict[str, dict] = {}

    def walk(branches) -> None:
        for branch in branches or []:
            if branch.get("category") == "product_version_range":
                product_id = ((branch.get("product") or {}).get("product_id"))
                parsed = parse_csaf_range_expression(branch.get("name"))
                if product_id and parsed:
                    ranges_by_product[product_id] = parsed
            walk(branch.get("branches"))

    walk((advisory_json or {}).get("product_tree", {}).get("branches"))

    by_cve: dict[str, dict] = {}
    for vulnerability in (advisory_json or {}).get("vulnerabilities") or []:
        cve_id = vulnerability.get("cve")
        if not cve_id:
            continue
        affected = (vulnerability.get("product_status") or {}).get("known_affected") or []
        for product_id in affected:
            if product_id in ranges_by_product:
                by_cve[cve_id] = ranges_by_product[product_id]
                break
    return by_cve


def version_status_for_range(
    firmware_version: str | None, version_range: dict | None,
) -> tuple[str, str | None]:
    """(status, fixed_version) for one CVE against one device's firmware.

    `not_affected` is only ever returned when both sides parsed cleanly and
    the comparison was unambiguous. Everything doubtful resolves `unknown`:
    in a security tool a false "you're safe" is a worse failure than an
    unresolved question.
    """
    if not version_range or version_range.get("ambiguous"):
        return STATUS_UNKNOWN, None
    if version_range.get("unbounded"):
        # A real assertion from NVD/CSAF that every version is affected, and
        # no fix version exists to compare against.
        return STATUS_AFFECTED_NO_FIX, None

    current = parse_version(firmware_version)
    if current is None:
        return STATUS_UNKNOWN, None

    # Below a lower bound means the range does not describe this device.
    for key, strictly in (("start_including", False), ("start_excluding", True)):
        bound = parse_version(version_range.get(key))
        if bound is None:
            continue
        a, b = _padded(current, bound)
        if (a <= b) if strictly else (a < b):
            return STATUS_NOT_AFFECTED, None

    for key, inclusive in (("end_excluding", False), ("end_including", True)):
        raw_bound = version_range.get(key)
        bound = parse_version(raw_bound)
        if bound is None:
            continue
        a, b = _padded(current, bound)
        affected = (a <= b) if inclusive else (a < b)
        return (STATUS_AFFECTED if affected else STATUS_NOT_AFFECTED), raw_bound

    # A start bound the device is at or above, with no end bound: the range
    # is open-ended, so it does affect this device, with no fix to point at.
    if version_range.get("start_including") or version_range.get("start_excluding"):
        return STATUS_AFFECTED_NO_FIX, None
    return STATUS_UNKNOWN, None


def rollup_firmware_currency(device_cves: list[dict], sources_checked: list[str]) -> dict:
    """One overall answer for a device, from its per-CVE statuses.

    Precedence: outdated > affected_no_fix > unknown > current.

    `current` is deliberately the hardest status to earn - it requires that
    something actually resolved AND that nothing is unresolved. Erring toward
    `unknown` over `current` is the whole point: this is a security tool, and
    a false "you are up to date" is the worst possible output.
    """
    statuses = [cve.get("version_status") for cve in device_cves]
    affected = [cve for cve in device_cves if cve.get("version_status") == STATUS_AFFECTED]
    no_fix = [s for s in statuses if s == STATUS_AFFECTED_NO_FIX]
    unknown = [s for s in statuses if s == STATUS_UNKNOWN]
    not_affected = [s for s in statuses if s == STATUS_NOT_AFFECTED]

    if affected:
        fixes = sorted({cve["fixed_version"] for cve in affected if cve.get("fixed_version")})
        detail = f" The earliest published fix is {fixes[0]}." if fixes else ""
        status = CURRENCY_OUTDATED
        reason = (
            f"{len(affected)} published CVE(s) are fixed in a firmware version newer than the one "
            f"this device reports.{detail}"
        )
    elif no_fix:
        status = CURRENCY_AFFECTED_NO_FIX
        reason = (
            f"{len(no_fix)} published CVE(s) are recorded as affecting every version of this "
            "product, with no fixed version published - so updating firmware would not resolve "
            "them. This is a real finding, not an unresolved comparison."
        )
    elif unknown or not not_affected:
        status = CURRENCY_UNKNOWN
        reason = (
            "No published CVE could be compared against this device's reported firmware version, "
            "so its currency could not be determined. This is missing data, not a clean result."
        )
    else:
        status = CURRENCY_CURRENT
        reason = (
            f"This device's firmware is at or above the fixed version of all {len(not_affected)} "
            "published CVE(s) that could be compared."
        )

    return {
        "status": status,
        "reason": reason,
        "sources_checked": list(sources_checked),
        "affected_count": len(affected),
        "affected_no_fix_count": len(no_fix),
        "not_affected_count": len(not_affected),
        "unknown_count": len(unknown),
    }
