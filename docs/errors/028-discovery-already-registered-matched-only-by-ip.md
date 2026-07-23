# ERR-028 — "Already registered" matched only by IP, missing every real lab device

- **Date:** 2026-07-23
- **Component:** lab/auditor/web/src/components/devices/NetworkDiscoveryPanel.tsx
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (session work)

## What happened

While verifying the new discovery-first device registration flow live in a
browser, every one of the 6 already-registered lab devices still showed a
"Register" button after a real network scan, instead of "Already
registered."

## Exact error / symptom

Screenshot evidence: a completed scan listing `172.30.0.2` (already
registered as `device-partial`) through `172.30.0.8` (already registered as
`mqtt-broker-insecure`) all showed a clickable "Register" button, with zero
"Already registered" labels anywhere on the page.

## Environment

- Real browser session (headless Playwright) against the live
  `auditor-web`/`auditor-api` stack.
- Relevant file: `NetworkDiscoveryPanel.tsx`'s `registeredHosts` set.

## Root cause

The already-registered check was:

```ts
const registeredHosts = new Set(devices.filter((d) => d.registered && d.host).map((d) => d.host as string));
// ...
const alreadyRegistered = registeredHosts.has(host.ip);
```

This assumes a registered device's `host` field is the IP the scan
discovered. But this lab's own seeded devices register with the **container
name** as `host` (e.g. `"device-partial"`), never the IP — `device_validation.py`
accepts either form, and the seed data happens to use container names. So
`registeredHosts` was really a set of container-name strings, being compared
against `host.ip` (an actual IP string like `"172.30.0.2"`) — they can never
match, so every device slipped through as "unregistered" regardless of its
real state.

## The fix

Replaced the IP-only set lookup with `isAlreadyRegistered()`, which derives
the same container-name guess `prefillFromHost()` already computes
(`suggestNameFromHost()`, parsing this lab's own
`kaust-iot-lab-<name>-<index>.<network>` hostname convention) and checks a
discovered host against a registered device's `host` **or** `device_id`, in
addition to the IP:

```ts
function isAlreadyRegistered(host: DiscoveredHost, devices: Device[]): boolean {
  const { deviceId } = suggestNameFromHost(host);
  return devices.some(
    (d) => d.registered && (d.host === host.ip || d.host === deviceId || d.device_id === deviceId),
  );
}
```

Re-verified live afterward: all 6 real, already-registered devices
correctly show "Already registered."

## How to prevent it next time

When matching a discovered/external identifier (an IP, a hostname) against
an internal record, don't assume the internal record uses the same
identifier space — check what the actual seed/registration data uses first.
Added two regression tests (`NetworkDiscoveryPanel.test.tsx`) covering both
matching paths (IP-based and container-name-based) so either one breaking
independently gets caught.

## References

- `lab/auditor/api/device_validation.py::validate_host` — confirms both a
  container name and an IP inside `172.30.0.0/24` are equally valid `host`
  values, which is exactly why this couldn't be "fixed" by picking one form
  to always expect.
