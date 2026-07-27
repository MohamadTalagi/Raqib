# Error & Solution Log

Every error we hit while building this project gets its **own Markdown file** here. These logs
feed our research report later, so we capture them even when the error is small.

## How to add an entry

1. Copy `ERROR_TEMPLATE.md` to a new file named `NNN-short-slug.md`
   (increment `NNN`, use a short kebab-case slug — e.g. `001-docker-compose-port-conflict.md`).
2. Fill in every section.
3. Add a one-line row to the index table below.

## Index

| ID | Title | Component | Date | Status |
|----|-------|-----------|------|--------|
| [001](001-npx-enoent-windows-mcp.md) | `spawn npx ENOENT` on Windows MCP launch | ssh-mcp / MCP servers | 2026-07-07 | resolved |
| [002](002-pydantic-core-no-py314-wheel.md) | `pydantic-core` has no Python 3.14 wheel, source build fails (no MSVC linker) | lab/devices/smart-camera | 2026-07-08 | resolved |
| [003](003-docker-credstore-fails-over-ssh.md) | Docker `credsStore: desktop` fails over non-interactive SSH session | build PC / Docker Desktop | 2026-07-08 | resolved |
| [004](004-docker-buildx-attestation-manifest-already-exists.md) | `docker build` succeeds but reports "image already exists" (buildx attestation manifest) | build PC / Docker Desktop | 2026-07-08 | resolved |
| [005](005-busybox-nc-localhost-ipv6-healthcheck.md) | BusyBox `nc -z localhost <port>` healthcheck fails for an IPv4-only-bound server | lab/telnet-sim | 2026-07-08 | resolved |
| [006](006-openssl-seclevel-rejects-weak-1024bit-cert.md) | OpenSSL SECLEVEL rejects the intentionally weak 1024-bit cert (`EE_KEY_TOO_SMALL`) | lab/devices/smart-camera | 2026-07-08 | resolved |
| [007](007-mosquitto-nonroot-cant-read-broker-key.md) | `mqtt-broker-secure` exits (code 13) — non-root mosquitto user can't read the 600-permission broker key | lab/certs, lab/mqtt/secure | 2026-07-08 | resolved |
| [008](008-plan-path-mismatch-auditor-worker.md) | Plan's own test code contradicted its stated file paths (`auditor.worker` vs `lab/auditor/worker`) | implementation plan (Tasks 23-26) | 2026-07-08 | resolved |
| [009](009-task23-accidentally-deleted-task22-files.md) | Task 23's implementer accidentally deleted Task 22's already-committed files | subagent-driven-development process | 2026-07-08 | resolved |
| [010](010-container-mount-missing-lab-prefix.md) | `auditor-worker`'s volume mount didn't include the `lab/` segment, breaking `lab.`-prefixed imports | lab/docker-compose.yml | 2026-07-08 | resolved |
| [011](011-record-evidence-script-invocation-needs-pythonpath.md) | `record_evidence.py` fails with `ModuleNotFoundError` when run as a plain script (needs `PYTHONPATH`) | lab/docker-compose.yml, record_evidence.py | 2026-07-08 | resolved |
| [012](012-psycopg-binary-3-2-3-no-wheel.md) | `psycopg[binary]==3.2.3` has no available wheel on PyPI | lab/auditor/api | 2026-07-08 | resolved |
| [013](013-plan-verdict-shape-mismatch-with-real-schema.md) | Plan's verdict test fixtures used dict-shaped `matched`/`saudi_source`, contradicting the real committed schema and `evaluate()`'s actual contract | Phases 6-8 plan (Tasks 4, 6, 8) | 2026-07-08 | resolved |
| [014](014-record-evidence-sequence-collision-after-api-migration.md) | `record_evidence.py`'s sequence numbering would collide on every repeated invocation after moving to API-based writes | lab/auditor/worker/tests/record_evidence.py | 2026-07-08 | resolved |
| [015](015-missing-flutter-web-platform-scaffold.md) | Flutter project was missing the `web/` platform directory, breaking `flutter build web` | lab/auditor/web | 2026-07-08 | resolved |
| [016](016-disk-space-exhaustion-corrupts-docker-containerd.md) | PC disk space exhaustion corrupted Docker Desktop's containerd storage and port-forwarding proxy | build PC / Docker Desktop | 2026-07-08 | resolved |
| [017](017-internal-network-blocks-docker-desktop-port-forwarding.md) | `internal: true` Docker network silently blocks Docker Desktop's host port-forwarding proxy | lab/docker-compose.dev.yml | 2026-07-08 | resolved |
| [018](018-erasable-syntax-only-blocks-parameter-properties.md) | `erasableSyntaxOnly` rejects TypeScript constructor parameter-property shorthand | lab/auditor/web (React) | 2026-07-09 | resolved |
| [019](019-host-port-8080-conflict-on-shared-dev-machine.md) | Host port 8080 already bound by an unrelated process on the shared dev machine | lab/auditor/web (Docker verification) | 2026-07-09 | resolved |
| [020](020-hardcoded-localhost-api-url-breaks-over-tailscale.md) | Hardcoded `localhost:8000` API URL baked into the build breaks the dashboard for any client but the PC itself | lab/auditor/web / lab/auditor/api | 2026-07-09 | resolved |
| [021](021-postgres-init-sql-does-not-rerun-on-existing-volume.md) | Adding a table to `init.sql` doesn't reach an already-created database (Postgres only runs init scripts on a fresh volume) | lab/auditor/db / lab/auditor/api | 2026-07-12 | resolved |
| [022](022-telnet-sim-healthcheck-busybox-nc-and-ipv6-localhost.md) | `telnet-sim` reports `Up (unhealthy)` for days — BusyBox `nc` has no `-z` flag, plus `localhost` resolves to IPv6 while the service binds IPv4 only | lab/docker-compose.yml | 2026-07-19 | resolved |
| [023](023-tcpdump-capture-attach-race-on-docker-desktop-wsl2.md) | tcpdump's "listening on" banner doesn't guarantee the capture ring buffer is attached yet — a single fetch right after it non-deterministically missed the packet | lab/auditor/worker/scan_scripts/packet_capture.py | 2026-07-21 | resolved |
| [024](024-conflict-detection-unhashable-list-observations.md) | Evidence conflict detection crashed with `TypeError: unhashable type: 'list'` on a real list-valued observation field (`open_ports`) | policies/engine/conflict.py | 2026-07-22 | resolved |
| [025](025-not-applicable-confused-with-not-automated.md) | Every device was wrongly marked `NOT_APPLICABLE` for SA-IOT-001 because its required test has no automated collector at all — conflated "not yet automated" with "doesn't apply" | policies/engine/policy_engine.py | 2026-07-22 | resolved |
| [026](026-nmap-multiport-regex-swallows-next-port-via-s-newline.md) | A port-table regex used `\s+` (matches the newline) instead of `[ \t]+`, so a no-version port line swallowed the next port's whole line as its own "version" | policies/catalog/scan_tests.py | 2026-07-23 | resolved |
| [027](027-docker-file-mount-created-empty-shadow-file-on-host.md) | An ad hoc Docker file-bind-mount test run left an empty file on the host that shadowed the real `device_validation.py`, crash-looping the live `auditor-worker` container | auditor-worker / device_validation.py | 2026-07-23 | resolved |
| [028](028-discovery-already-registered-matched-only-by-ip.md) | Network-discovery's "Already registered" check matched only by IP, missing every real lab device (which registers with a container name as `host`, not an IP) | lab/auditor/web/src/components/devices/NetworkDiscoveryPanel.tsx | 2026-07-23 | resolved |
| [029](029-network-discovery-open-flag-made-unknown-classification-dead-code.md) | nmap's `--open` flag silently omitted live hosts with no signature port open, making the `"unknown"` classification unreachable from real scan output | policies/catalog/scan_tests.py | 2026-07-23 | resolved |
| [030](030-firmware-upload-accept-tar-gz-greyed-out-on-windows.md) | Firmware `.tar.gz` files greyed out / unselectable in the Windows file picker because `accept=".tar.gz,.tgz"` relies on shell type associations that only map the trailing `.gz` | auditor-web | 2026-07-27 | resolved |
