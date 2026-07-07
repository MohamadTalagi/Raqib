# ERR-002 — pydantic-core has no prebuilt wheel for Python 3.14, build-from-source fails (no MSVC linker)

- **Date:** 2026-07-08
- **Component:** lab/devices/smart-camera (Phase 0-5 implementation plan, Task 4)
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 4 implementer + controller follow-up)

## What happened
Task 4 of the Phase 0-5 implementation plan pinned `pydantic==2.9.2` in
`lab/devices/smart-camera/requirements.txt`. Installing it into a venv on the laptop (Python 3.14.3)
failed because its dependency `pydantic-core==2.23.4` has no prebuilt wheel for `cp314-win_amd64` and
pip fell back to building it from source (it's a Rust extension via maturin/PyO3), which failed at
the linking step.

## Exact error / symptom
```
error: linking with `link.exe` failed: exit code: 1
  ...
error: could not compile `rustversion` (build script) due to 1 previous error
error: could not compile `target-lexicon` (build script) due to 1 previous error
error: could not compile `libc` (build script) due to 1 previous error
error: could not compile `radium` (build script) due to 1 previous error
error: could not compile `num-traits` (build script) due to 1 previous error
error: could not compile `memoffset` (build script) due to 1 previous error
💥 maturin failed
  Caused by: Failed to build a native library through cargo
ERROR: Failed building wheel for pydantic-core
```

## Environment
- OS / shell: Windows 11, Git Bash (git-bash.exe), Python 3.14.3 (MSC v.1944 64 bit)
- Tool + version: pip 25.3, pydantic 2.9.2 -> pydantic-core 2.23.4 (sdist only for this platform/Python combo)
- Relevant files: `lab/devices/smart-camera/requirements.txt`

## Root cause
`pydantic-core` ships prebuilt wheels only for the Python versions/platforms its release covered at
publish time. Python 3.14 is very new; `pydantic-core==2.23.4` (the version `pydantic==2.9.2` pins)
predates 3.14 wheel builds, so pip must compile the Rust extension locally — which needs a working
Rust toolchain wired to a working MSVC linker. Neither is correctly set up in this environment
(`link.exe` invocation fails), so the build fails and the whole `pip install` aborts.

## The fix
Bumped the pin to `pydantic==2.13.4`, whose `pydantic-core==2.46.4` dependency does ship a
`cp314-win_amd64` wheel — confirmed to install cleanly, and confirmed compatible with the already-pinned
`fastapi==0.115.0` and `pydantic-settings==2.5.2` (no other version changes needed).

```
# lab/devices/smart-camera/requirements.txt
- pydantic==2.9.2
+ pydantic==2.13.4
```

Verification:
```
pip install pydantic==2.13.4 pydantic-settings==2.5.2 fastapi==0.115.0
# Successfully installed ... pydantic-2.13.4 pydantic-core-2.46.4 ...
```

## How to prevent it next time
When pinning exact versions of any package with a compiled/Rust extension (pydantic-core, tiktoken,
cryptography, etc.) in a plan meant to run on a very new Python version, verify a prebuilt wheel
exists for that Python/platform combo before pinning — e.g. `pip download <pkg>==<version> --no-deps -d /tmp/x`
and check whether the resolved file is a `.whl` (fine) or a `.tar.gz` sdist (risk of a from-source
build that may fail without a full compiler toolchain). Prefer the newest patch/minor version of such
packages unless an older one is specifically required, since newer releases are more likely to have
wheels for newer Python versions.

## References
None external — diagnosed directly via `pip install` output in this session.
