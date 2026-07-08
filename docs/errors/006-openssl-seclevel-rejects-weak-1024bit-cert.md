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
Debian's OpenSSL 3.x ships a system-wide crypto policy with a default `SECLEVEL` that rejects RSA
keys below ~2048 bits outright — `ctx.load_cert_chain()` fails before the server can even bind. This
is the exact opposite of what the lab needs to demonstrate: `device-partial`'s 1024-bit/SHA-1 cert is
an **intentional** lab fixture modeling a legacy/vulnerable device that a real attacker could still
exploit — a real vulnerable device wouldn't refuse to start over its own weak key, it would happily
serve it (that's the vulnerability).

**First fix attempt failed:** setting `OPENSSL_CONF` to a config file with `CipherString =
DEFAULT@SECLEVEL=0` works for the `openssl` CLI (verified directly) but has **zero effect on
Python** — CPython's `ssl` C extension initializes OpenSSL with `OPENSSL_INIT_NO_LOAD_CONFIG`,
deliberately skipping the system config file (and `OPENSSL_CONF`) for determinism/security reasons.
Since uvicorn's server-side context and the healthcheck's client-side context are both created via
Python's `ssl` module, `OPENSSL_CONF` never took effect and the crash was identical even with the
env var confirmed set correctly inside the container.

## The fix
Lower the security level in Python code, explicitly, at the two places `ssl.SSLContext` objects get
created in this image:

1. **Server side (uvicorn):** `lab/devices/smart-camera/sitecustomize.py` monkeypatches
   `ssl.SSLContext.load_cert_chain` to call `self.set_ciphers("DEFAULT@SECLEVEL=0")` before loading
   — `sitecustomize.py` is auto-imported by every Python process when its directory is on
   `PYTHONPATH` (set via `ENV PYTHONPATH=/app` in the Dockerfile), so this applies without touching
   `app/main.py` or `entrypoint.sh`.
2. **Client side (the Dockerfile's own HEALTHCHECK):** added `ctx.set_ciphers('DEFAULT@SECLEVEL=0')`
   right after `ssl.create_default_context()`, since the client's own TLS handshake against a
   weak-keyed server is independently subject to the same security-level check.

**A broader monkeypatch attempt (reassigning `ssl.SSLContext` itself to a subclass) was tried first
and rejected** — `ssl.py`'s own internal methods (e.g. the `verify_mode` property setter) call
`super(SSLContext, SSLContext)` referencing the module-global `SSLContext` name for their own
super-class resolution; reassigning that name broke those internal self-references and caused
infinite recursion (`RecursionError: maximum recursion depth exceeded`). Patching only the specific
method (`load_cert_chain`) avoids this entirely, since it doesn't change the class object's identity.

This is scoped to the smart-camera image only and does not weaken `device-hardened`'s actual
security — that device's strength comes from genuinely using a 2048-bit/SHA-256 key, not from this
gate.

## How to prevent it next time
When a lab/test fixture deliberately uses weak cryptographic parameters to simulate a vulnerable
system, check whether the *tooling* (not just the target) enforces a minimum security policy that
would prevent the fixture from running at all. For Python specifically, `OPENSSL_CONF` is **not** a
reliable lever — CPython skips OpenSSL's config auto-loading — so the fix must happen via the `ssl`
module's Python API (`SSLContext.set_ciphers()`) called before certificate loading, not via the
environment/config-file mechanism that works for other OpenSSL-linked CLI tools.

## References
None external — diagnosed directly via `docker logs` output and isolated `python -c` tests in this session.
