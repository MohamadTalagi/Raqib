# ERR-004 — `docker build` succeeds but reports "image already exists" (buildx attestation manifest)

- **Date:** 2026-07-08
- **Component:** build PC (OSRA-PC2025-V2) / Docker Desktop buildx (containerd image store)
- **Severity:** low
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 7 controller-side PC verification)

## What happened
`docker build -t smart-camera:local .` ran all build stages successfully (base image, deps,
COPY, chmod) and got to "exporting to image," but then reported a failure. Checking `docker images`
afterward showed the image had, in fact, been created and tagged correctly — the reported failure
was misleading.

## Exact error / symptom
```
#13 exporting manifest list sha256:5c6d6f03b4c83fc6545f548e81b7d6e82076b396464d5b3c34618be41b1a4e2f 0.1s done
#13 naming to docker.io/library/smart-camera:local done
#13 ERROR: image "docker.io/library/smart-camera:local": already exists
------
ERROR: failed to build: failed to solve: image "docker.io/library/smart-camera:local": already exists
```
`docker images smart-camera` immediately after this "error" showed a valid, correctly dated image.

## Environment
- OS / shell: Windows 11, Docker Desktop 29.1.3, buildx with the `desktop-linux` driver, containerd
  image store, default build attestations enabled
- Relevant files: `lab/devices/smart-camera/Dockerfile`

## Root cause
With the containerd snapshotter/image store and default provenance/attestation manifests enabled,
buildx exports the image twice: once as the plain single-platform image (which succeeds and is what
`docker images` sees), then attempts to also write a manifest-list wrapper carrying the attestation
under the same tag — which collides with the tag it just wrote a moment earlier, producing a
spurious "already exists" error on an otherwise-successful build.

## The fix
Rebuild with `--provenance=false` to skip attestation-manifest generation entirely:
```
docker build --provenance=false -t smart-camera:local .
```
This built cleanly with no error, using the cache from the first (apparently-failed) build.

## How to prevent it next time
When a `docker build` errors only at the final "exporting to image" step with "image ... already
exists," check `docker images <tag>` before assuming the build actually failed — it may have
succeeded despite the error. Add `--provenance=false` to `docker build` invocations in this lab's
plan/scripts going forward to avoid the spurious error and the wasted rebuild-and-recheck cycle.

## References
None external — diagnosed directly via `docker build`/`docker images` output in this session.
