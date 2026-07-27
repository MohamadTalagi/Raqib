# ERR-030 — Firmware upload: `.tar.gz` files greyed out / unselectable in the Windows file picker

- **Date:** 2026-07-27
- **Component:** auditor-web (device detail page + register device form)
- **Severity:** high
- **Status:** resolved
- **Author:** osamapcrabigh

## What happened
The owner reported "I cannot upload a firmware" from the dashboard. The
backend `POST /devices/{id}/firmware` endpoint and its CORS preflight both
work (verified live via curl — HTTP 201 for a real `.tar.gz`, and a 200
`OPTIONS` preflight with `access-control-allow-methods: POST`), so the
failure was entirely in the browser file-selection step, not the upload
itself.

## Exact error / symptom
```
# Backend works fine:
$ curl -X POST -F "firmware=@fw.tar.gz" http://localhost:8000/devices/device-insecure/firmware
{... "firmware_filename":"fw.tar.gz" ...}  HTTP 201

# In the browser on Windows: opening the file picker from the Firmware card,
# the user's real .tar.gz archive appears greyed out / not selectable, so
# onChange never fires and the "Upload firmware" button stays disabled.
```

## Environment
- OS / shell: Windows 11, Chrome
- Relevant files:
  - `lab/auditor/web/src/pages/DeviceDetailPage.tsx` (Firmware card `<input type="file">`)
  - `lab/auditor/web/src/components/devices/RegisterDeviceForm.tsx` (optional firmware field)
  - `lab/auditor/api/main.py::upload_device_firmware` (unchanged — already correct)

## Root cause
Both file inputs used `accept=".tar.gz,.tgz"`. Windows' native Open dialog
maps a file to only the **final** extension of a compound name — `.tar.gz`
is registered as `.gz`, not as a distinct `.tar.gz` type. Chrome on Windows
builds the picker's type filter from `accept`, so a bare `.tar.gz`/`.tgz`
filter does not match real `.tar.gz` files and they render greyed out. The
user has to manually switch the picker's dropdown to "All files" to select
the archive — non-obvious, so it reads as "I can't upload firmware." The
button's `disabled={!pendingFirmwareFile}` guard then keeps Upload disabled
because no file was ever selected.

## The fix
Broaden `accept` on both inputs to include `.gz` and the gzip/tar MIME types,
so the archive is directly selectable. The API still gates on the real
`.tar.gz`/`.tgz` filename (`upload_device_firmware`), so nothing about the
security boundary changes.

```
- accept=".tar.gz,.tgz"
+ accept=".tar.gz,.tgz,.gz,application/gzip,application/x-gzip,application/x-compressed-tar,application/x-tar"
```

Rebuilt and redeployed `auditor-web`; confirmed the broadened `accept` string
is in the served JS bundle.

## How to prevent it next time
For any file input that accepts a **compound extension** (`.tar.gz`,
`.tar.bz2`, ...), never rely on the compound token alone in `accept` — also
list the final single extension and the MIME type(s), or omit `accept`
entirely and enforce the type server-side (which this endpoint already does).
Keep the real validation on the backend, treat `accept` as a UX filter only.

## References
- Chromium behavior: `accept` with compound extensions on Windows relies on
  shell file-type associations, which only recognize the trailing extension.
