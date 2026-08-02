# Post-Quantum Readiness (bonus pipeline stage)

## What this is

Not one of IoTGuard's original 10 stages (`docs/reference/IoTGuard.md`) — a bonus
check the project owner asked for on top of the vision: does a device's live TLS
posture and firmware actually use post-quantum-safe cryptography? Sits in the
pipeline **after AI Remediation (Stage 07) and before the AI Executive Summary
(Stage 08)**, so its findings flow into the executive rollup rather than
dead-ending on their own page.

**Explicitly informational only.** It never touches `policies/risk/risk_engine.py`,
never becomes a fourth SA-IOT/NCA-style compliance framework requiring sign-off, and
never affects a device's risk score, risk category, or compliance readiness
classification. Every API response and every UI surface says so.

## Design decisions (agreed with the project owner before implementation)

1. **Remediation tips are static, deterministic text**, not AI-generated — matches
   this project's dominant "AI-assisted, not AI-decided" convention, and this is a
   narrow enough domain (3 fixed criteria) that fixed guidance is genuinely accurate
   for every case it can reach.
2. **Included in the Fully Automated Run**, unlike AI Remediation (which stays
   manual-only) — the owner's explicit choice, more aggressive than this session's
   own default recommendation of manual-only.

## No enforceable regulation exists yet

Unlike NCA CGIoT-1:2024, which this project maps against real clauses, there is no
real, enforceable "IoT post-quantum regulation" to check against today. This feature
checks three named **technical criteria** grounded in real NIST standards (FIPS 203
ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) instead of a fabricated regulatory
citation — stated honestly in the UI copy, the API, and this doc, never glossed over
as a compliance framework.

## The 3 criteria

1. **TLS Key Exchange (KEM)** — `pass` if the negotiated TLS 1.3 group is a hybrid
   PQC group; `fail` if a classical-only group negotiated despite PQC options being
   offered; `not_applicable` if the device has no TLS-capable service at all.
2. **Certificate Signature Algorithm** — `pass` if the certificate's own signature
   algorithm is ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); `fail` if
   RSA/ECDSA/DSA (classical); `not_applicable` with no TLS service.
3. **Firmware Crypto Library Currency** — `pass` if a firmware-manifest package
   recognized as a TLS/crypto library meets a verified PQC-capable version
   threshold; `fail` if below it; **`unknown`** (never a guessed fail) for an
   unrecognized library name or no firmware uploaded — guessing a threshold for a
   library this project hasn't verified would be exactly the kind of unverified
   claim this project avoids everywhere else.

`unknown` and `not_applicable` are both real, honest states distinct from `fail` —
"couldn't determine" and "nothing to check here" are never reported as a failure.

## What was verified live before designing this (not assumed)

Checked directly against the real `auditor-worker` container and real lab devices,
since a tool with no PQC support of its own can't meaningfully test for it:

- `auditor-worker`'s OpenSSL is **3.5.6**. `openssl list -tls1_3 -tls-groups` shows
  it natively supports exactly **3** hybrid TLS 1.3 groups: `X25519MLKEM768`,
  `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` (all wrapping NIST FIPS 203 ML-KEM), plus
  `ML-DSA-44/65/87` (FIPS 204) and `SLH-DSA` (FIPS 205) signature algorithms.
- Real result against `device-hardened:443`/`device-partial:443`: **`Negotiated
  TLS1.3 group: X25519MLKEM768`** — this lab's own HTTPS devices already negotiate a
  real hybrid PQC key exchange, a genuine surprise worth confirming rather than
  assuming "everything will fail."
- The certificate itself is classical: `sha256WithRSAEncryption`, 2048-bit RSA —
  not ML-DSA/SLH-DSA. Key exchange and certificate signature genuinely disagree in
  this lab today, which honestly reflects the real world (PQC key-exchange rollout
  is ahead of PQC certificate/PKI rollout industry-wide).
- Only 2 of 11 registered devices have `https` (`device-hardened`/`device-partial`);
  `mqtt-broker-secure` has `mqtts`. `device-insecure` has no TLS service at all — a
  TLS-based check must report `not_applicable`, never "not ready," for a device with
  nothing to test.

## A real bug caught by the first live run, not by unit tests alone

The original group list passed to `openssl s_client -groups` included a 4th
hybrid name, `X448MLKEM1024`, assumed by analogy with the other 3 pairings
without first checking `openssl list -tls1_3 -tls-groups`'s actual output. That
name does not exist in OpenSSL's real hybrid-group registry — ML-KEM-1024 only
pairs with SecP384r1, not X448. Passing an unrecognized name inside `-groups`
made OpenSSL reject the **entire** colon-separated argument outright
(`Call to SSL_CONF_cmd(-groups, ...) failed`), so every single TLS-capable device
in the lab reported `connection_error` instead of a real result — the first live
scan against `device-hardened` surfaced this immediately.

Fixed by removing `X448MLKEM1024` from both `PQC_HYBRID_GROUPS` constants
(`lab/auditor/worker/scan_scripts/pqc_readiness_check.py`'s command-building list
and `policies/catalog/scan_tests.py`'s classification set) and re-verifying live:
a real handshake against `device-hardened` now negotiates `X25519MLKEM768`
exactly as expected, and the certificate-signature criterion correctly reports
`fail` (`sha256WithRSAEncryption`). Both existing unit-test suites
(`policies/catalog/test_scan_tests.py`, `lab/auditor/worker/test_automated_run_runner.py`)
continued to pass unchanged since neither ever asserted the exact group-name list —
a live scan was the only way this was ever going to be caught.

## Backend

- **`policies/catalog/pqc_crypto_reference.py`** — a small, explicitly
  OpenSSL-only, version-gated lookup table (`CRYPTO_LIBRARY_PQC_THRESHOLDS`,
  currently just `openssl >= 3.2.0`) plus the 3 criteria's fixed, deterministic tip
  text, each grounded in a real command/version number confirmed live above.
  Extending to wolfSSL/BoringSSL/mbedTLS is a real follow-up needing its own
  verified version research, not invented here.
- **`lab/auditor/worker/scan_scripts/pqc_readiness_check.py`** — mirrors
  `tls_cert_check.py`'s two-handshake shape: one `s_client` handshake (PQC groups
  offered first, classical groups as a fallback so a non-PQC server still
  completes a handshake) for the negotiated group, a second `-showcerts` handshake
  piped into `openssl x509 -noout -text` for the certificate's own signature
  algorithm (`-brief` suppresses the PEM even together with `-showcerts`,
  confirmed live, same as `tls_cert_config`).
- **`policies/catalog/scan_tests.py`**: new `PIPELINE_PHASE_PQC_READINESS`
  constant; two new `SCAN_CATALOG` entries —
  `TEST-PQC-TLS-HANDSHAKE` (`applicable_service_types = TLS_SERVICE_TYPES`, reused
  as-is from the existing TLS collector) and `TEST-PQC-FIRMWARE-CRYPTO`
  (firmware-scoped like `TEST-FW-MANIFEST`, reusing `firmware_check.py`'s existing
  manifest-parsing entry point rather than re-parsing the manifest itself).
- **`lab/auditor/api/pqc_routes.py`** — read-only, computed live from `evidence`
  rows on every request, same architecture as `vuln_routes.py`/`risk_routes.py`.
  No new table, no new verdict/assessment concept.
  - `GET /pqc-readiness/devices` — every device, worst-first by failing-criterion
    count.
  - `GET /pqc-readiness/devices/{id}` — one device's full 3-criterion breakdown +
    tip text for any failing criterion. `known: false` (not a 404) for an
    unregistered device.
  - `GET /pqc-readiness/fleet-summary` — pass/fail/unknown/not_applicable counts
    per criterion, fleet-wide, via a shared `fleet_summary_from_devices()` helper
    also reused by `executive_summary.py` so the two can never disagree.
- **`lab/auditor/worker/automated_run_runner.py`** — a new `pqc_readiness` stage
  between `vulnerability_intelligence` and `nca_compliance`. `_run_pqc_readiness()`
  runs `TEST-PQC-TLS-HANDSHAKE` on any device with an applicable TLS service and
  `TEST-PQC-FIRMWARE-CRYPTO` only on a device that already has firmware uploaded
  (never invented) — a new `summary["pqc_devices_scanned"]` counter reports how
  many devices this stage actually touched. Deliberately **not** added to
  `AUTOMATED_TEST_PHASES` (which drives the fingerprinting/SA-IOT stage's own test
  selection) — a dedicated `_pqc_applicable_test_ids()` keeps this stage's test
  selection separate so it can't be misplaced into the wrong pipeline stage.
- **`executive_summary.py`** — `build_executive_summary_model()` calls
  `pqc_routes._device_pqc_summary()` per device (reused, not reimplemented) and
  adds a top-level `post_quantum_readiness` fleet rollup. Kept deliberately
  separate from `risk_score`/`fleet_summary`'s existing fields — its own section,
  never blended into the compliance-gap counts. The PDF/HTML template gained a
  per-device breakdown and a fleet-wide section 5.

## Frontend

- **`/pqc-readiness`** (`PostQuantumReadinessPage.tsx`) — inserted in the sidebar's
  Pipeline group between Remediation and Executive Summary, matching the requested
  pipeline placement. Same `DeviceCohortPicker` + per-device
  `PhaseRunnerCard`-wrapping pattern `VulnerabilityIntelligencePage.tsx` already
  established (`DevicePqcReadinessCard.tsx`), plus a shared `PqcReadinessPanel`
  (`components/pipeline/PqcReadinessPanel.tsx`) showing the live 3-criterion
  breakdown and tip text, reused on both this page and the Executive Summary page's
  per-device panel so the two can never render differently.
- **New `PqcCriterionBadge`** (`severity-badge.tsx`) for the pass/fail/unknown/
  not_applicable status set.
- **`AutomatedRunDialog.tsx`** discloses the new stage in its confirmation copy
  before anything starts, matching this project's standing "state exactly what
  will run before any fleet-wide side effect" rule. `AutomatedRunProgressPage.tsx`
  shows a live "Post-quantum checks" stat tile.
- **`ExecutiveSummaryPage.tsx`** gained a fleet-wide "Post-Quantum Readiness
  (informational)" card and reuses `PqcReadinessPanel` inside each device's
  expanded detail panel.

## Verified live end to end

- Ran the real `TEST-PQC-TLS-HANDSHAKE` collector against `device-hardened` through
  the actual API/worker: real `is_pqc_kem: true` (`X25519MLKEM768`), real
  `is_pqc_signature: false` (`sha256WithRSAEncryption`) — exactly matching the
  pre-implementation live-verification findings above.
- Confirmed `device-insecure` (no TLS service) correctly rejects the scan job
  (`"test does not apply to this device's services"`) and its readiness endpoint
  reports `not_applicable` across all 3 criteria.
- Triggered a real scoped Fully Automated Run (`device-hardened`) and confirmed its
  summary reported `"pqc_devices_scanned": 1` — the new stage ran for real inside
  the orchestrated pipeline, not just when invoked directly.
- Confirmed `GET /pqc-readiness/fleet-summary` and `GET /executive-summary`'s
  `post_quantum_readiness` section agree byte-for-byte after the real scan.
- Confirmed the live HTML export (`GET /executive-summary/report.html`) renders
  both the real per-device row (`TEST-PQC-TLS-HANDSHAKE` evidence, real finding
  text) and the fleet-wide section 5 table with the real counts.
- Confirmed in a real browser (Claude-in-Chrome): the Executive Summary page
  renders the live "Post-Quantum Readiness (informational)" card with the same
  real counts the API returned, and the new `/pqc-readiness` route resolves and
  renders its device cohort picker.

Regression: 387 `policies` (+17) + 310 `lab/auditor/api` (3 pre-existing WeasyPrint
failures, unrelated) + 113 `lab/auditor/worker` (in-container, 0 failures) + 307
frontend tests (+22) passing, `tsc -b`/`oxlint` clean.

## Known limitations (stated up front)

- **No enforceable IoT PQC regulation exists** to check against — these are named
  technical criteria grounded in real NIST standards, not a regulatory citation.
- **The firmware crypto-library criterion only recognizes OpenSSL** (the one
  library/version-threshold actually verified here) — an unrecognized library
  reports `unknown`, never a guessed pass/fail. Extending to wolfSSL/BoringSSL/
  mbedTLS is a real follow-up, not invented now.
- **A `pass` on the TLS Key Exchange criterion reflects this project's own
  scanning host's OpenSSL 3.5.6 offering PQC groups** — a scanning host with an
  older OpenSSL would need this project's own `tls_cert_check.py`-style
  "untestable, never guessed" distinction if this collector were ever run
  elsewhere.
- **Explicitly never affects `risk_engine.py`'s inputs or score**, and never
  becomes a fourth SA-IOT/NCA-style compliance framework requiring sign-off —
  purely informational, matching the owner's own framing of this as a bonus check.
