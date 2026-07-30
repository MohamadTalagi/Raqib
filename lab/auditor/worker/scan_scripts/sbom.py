"""Build a minimal CycloneDX SBOM so Grype can scan a firmware package list.

Grype's stock CPE-based matcher only fires when a component carries an
explicit `cpe`, or when `--add-cpes-if-none` is passed at scan time (which
synthesizes one from the package name/version). A synthesized CPE only
matches real NVD data when the component's real CPE *vendor* slug happens
to equal its product name - confirmed true for "openssl"/"busybox" via a
live spike against the real Grype v0.82.0 database, and confirmed FALSE for
"mosquitto" (real vendor is "eclipse"), which silently matched zero CVEs
under synthesis alone.

CPE_OVERRIDES supplies the real vendor:product for names where synthesis is
known to be wrong, each one verified by hand against a real Grype scan
during that spike - never guessed. A name with no override still gets a
`purl`, so it's not excluded from scanning; it just relies on
`--add-cpes-if-none` at scan time and may under-match, same as today's
"no local reference data" honesty rule for anything unverified.
"""

CPE_OVERRIDES: dict[str, str] = {
    "mosquitto": "eclipse:mosquitto",
}


def build_cyclonedx_sbom(packages: list[tuple[str, str]]) -> dict:
    components = []
    for name, version in packages:
        component: dict = {"type": "library", "name": name, "version": version}
        override = CPE_OVERRIDES.get(name.strip().lower())
        if override:
            vendor, _, product = override.partition(":")
            component["cpe"] = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        else:
            component["purl"] = f"pkg:generic/{name}@{version}"
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }
