# ERR-006 — OpenSSL SECLEVEL rejects the intentionally weak 1024-bit cert (`EE_KEY_TOO_SMALL`)

- **Date:** 2026-07-08
- **Component:** lab/devices/smart-camera (device-partial profile)
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 16 controller-side integration verification)

## What happened
After wiring `device-partial` into `docker-compose.yml` (Task 16) and bringing the full lab up,
`device-partial` exited immediately with code 1 while every other service started fine.

## Exact error / symptom
```
File "/usr/local/lib/python3.12/site-packages/uvicorn/config.py", line 113, in create_ssl_context
    ctx.load_cert_chain(certfile, keyfile, get_password)
ssl.SSLError: [SSL: EE_KEY_TOO_SMALL] ee key too small (_ssl.c:3855)
```

## Environment
- OS / shell: `python:3.12-slim` (Debian-based) container, system OpenSSL 3.x
- Tool + version: uvicorn 0.30.6 loading a TLS cert chain via Python's `ssl` module
- Relevant files: `lab/devices/smart-camera/profiles/partial.env` (`TLS_CERTFILE=/certs/weak.crt`), `lab/certs/generate.sh` (generates the 1024-bit `weak.key`)

## Root cause
Debian's OpenSSL 3.x ships a system-wide crypto policy (`/etc/ssl/openssl.cnf`) with a default
`SECLEVEL` that rejects RSA keys below ~2048 bits outright — `ctx.load_cert_chain()` fails before
the server can even bind, regardless of TLS negotiation. This is the exact opposite of what the lab
needs to demonstrate: `device-partial`'s 1024-bit/SHA-1 cert is an **intentional** lab fixture
modeling a legacy/vulnerable device that a real attacker could still exploit — a real vulnerable
device wouldn't refuse to start over its own weak key, it would happily serve it (that's the
vulnerability).

## The fix
Added `lab/devices/smart-camera/openssl.cnf` setting `CipherString = DEFAULT@SECLEVEL=0`, and
`ENV OPENSSL_CONF=/app/openssl.cnf` in the Dockerfile so it applies inside the container:
```ini
[system_default_sect]
CipherString = DEFAULT@SECLEVEL=0
```
This is scoped to the smart-camera image only and does not weaken `device-hardened`'s actual
security — that device's strength comes from genuinely using a 2048-bit/SHA-256 key, not from
OpenSSL's policy gate.

## How to prevent it next time
When a lab/test fixture deliberately uses weak cryptographic parameters to simulate a vulnerable
system, check whether the *tooling* (not just the target) enforces a minimum security policy that
would prevent the fixture from running at all — modern OpenSSL's SECLEVEL is a common one. Relax it
explicitly and narrowly (only in the image that needs to demonstrate the weak posture) rather than
strengthening the fixture to work around the tooling, which would defeat the fixture's purpose.

## References
None external — diagnosed directly via `docker logs` output in this session.
