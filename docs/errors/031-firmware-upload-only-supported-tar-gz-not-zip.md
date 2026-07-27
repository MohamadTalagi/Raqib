# ERR-031 — Firmware upload only supported `.tar.gz`, not `.zip`

- **Date:** 2026-07-27
- **Component:** auditor-api + auditor-worker (firmware upload & analysis)
- **Severity:** high
- **Status:** resolved
- **Author:** osamapcrabigh

## What happened
Follow-up to [ERR-030]. After broadening the file picker's `accept` filter,
the owner clarified the real blocker: "it does not accept .zip files." Their
firmware archive was a `.zip` (the format Windows' right-click "Send to →
Compressed (zipped) folder" produces), but the entire firmware pipeline only
handled gzip-compressed tarballs.

## Exact error / symptom
```
POST /devices/{id}/firmware with a .zip file:
  400 {"detail": "firmware must be a .tar.gz or .tgz archive"}
```
Even had the extension been allowed, `_validate_firmware_archive` and the
worker's `scan_firmware.scan_archive()` / `firmware_check.py` all opened the
file with `tarfile.open(..., "r:gz")`, so a zip would have failed to parse.

## Environment
- OS / shell: Windows 11 (zip made via the Windows shell)
- Relevant files:
  - `lab/auditor/api/main.py` (`upload_device_firmware`, `_validate_firmware_archive`, `_firmware_path`)
  - `lab/auditor/worker/firmware/scan_firmware.py`
  - `lab/auditor/worker/scan_scripts/firmware_check.py`

## Root cause
The firmware feature was built against the lab's own synthetic fixtures,
which `generate_firmware.py` only ever produces as `.tar.gz`. Every stage —
upload validation, on-disk storage name (`{device_id}.tar.gz`), the YARA
secret scan, and the 7 structural `TEST-FW-*` checks — hardcoded `tarfile`.
A real user archive in `.zip` form had no path through the pipeline.

## The fix
Added a shared, format-agnostic archive abstraction and routed both worker
scripts through it, so `.tar.gz` and `.zip` are handled by one code path.

- New `lab/auditor/worker/firmware/archive_reader.py`: `open_archive(path)`
  detects gzip vs zip by **magic bytes** (not filename) and yields a uniform
  `Member` interface (`name`, `is_file`, `size`, `mode`, bounded `read(cap)`).
- `scan_firmware.py` and `firmware_check.py` iterate `archive.iter_members()`
  instead of calling `tarfile` directly; the zip-bomb caps
  (`MAX_MEMBER_BYTES` / `MAX_TOTAL_BYTES`) are preserved via the bounded read.
- API: accept `.zip` by extension, validate by magic bytes (tar **or** zip),
  reject unsafe member paths in both formats, and store under a format-neutral
  name `{device_id}.archive` (the original filename is kept only in
  `devices.firmware_filename` for display). `_firmware_path` /
  `_archive_path` both updated to match.
- Frontend: `.zip` (and its MIME types) added to both firmware `<input>`
  `accept` filters; helper text now says ".tar.gz or .zip".

```
# Verified live end to end:
POST /devices/device-insecure/firmware  (fw.zip)  -> 201, firmware_filename "fw.zip"
POST /scan-jobs {test_id: TEST-FW-MANIFEST}       -> worker read the zip,
     parsed manifest.json, matched openssl 1.0.1e -> real Heartbleed/CCS CVEs
```

## How to prevent it next time
When a feature reads user-supplied archives, support the formats users
actually produce on their OS (Windows makes `.zip` by default), and detect
format by content, not extension. Keep one archive-reading abstraction rather
than scattering `tarfile`/`zipfile` calls, so adding a format is a one-file
change. See [ERR-030] for the file-picker half of this same report.

## References
- [ERR-030] — the `accept` filter half of "I cannot upload a firmware".
