# ERR-015 — Flutter project was missing the `web/` platform directory, breaking `flutter build web`

- **Date:** 2026-07-08
- **Component:** lab/auditor/web (Phases 6-8 plan, Tasks 10-17)
- **Severity:** high
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 17 implementer identified it; controller fixed it)

## What happened
Tasks 10-16 built the entire Flutter dashboard by hand-writing `pubspec.yaml`, `lib/*.dart`, and `test/*.dart`
directly, since no Flutter SDK is installed anywhere in this environment (all `flutter test` runs went through
the `ghcr.io/cirruslabs/flutter:stable` Docker image). This approach never ran `flutter create`, which is
normally what generates a project's per-platform scaffold directories. Every `flutter test` in Tasks 10-16
worked fine without one — but Task 17's Dockerfile, which runs `flutter build web`, failed immediately with
"This project is not configured for the web," because the `web/` directory (`index.html`, `manifest.json`,
`favicon.png`, `icons/`) never existed.

## Exact error / symptom
```
Error: This project is not configured for the web.
To configure this project for the web, run flutter create --platforms=web .
```
(raised inside the Dockerfile's `RUN flutter build web --release ...` step)

## Environment
- Component: `lab/auditor/web/` (Flutter project root)
- Tool + version: Flutter (via `ghcr.io/cirruslabs/flutter:stable` Docker image), `flutter build web`

## Root cause
The plan's design decision to hand-write Dart source files (rather than running `flutter create`, since no
local Flutter SDK exists to run it against interactively during planning) covered every file `flutter test`
needs, but never accounted for the platform-specific `web/` directory that only `flutter build web`
(not `flutter test`) actually requires. This gap was invisible for 6 tasks (10-16) because none of them ran a
real web build — only `flutter test`, which doesn't need platform scaffolding.

## The fix
Ran `flutter create . --platforms web --project-name auditor_web --org com.iotguard` in an isolated temp
directory (seeded with only the project's `pubspec.yaml`, to avoid overwriting the hand-written `lib/main.dart`
or colliding with the existing `test/` files) via the same `ghcr.io/cirruslabs/flutter:stable` Docker image,
then copied only the generated `web/` directory into the real project — `web/index.html`, `web/manifest.json`,
`web/favicon.png`, `web/icons/*.png`. Deliberately did NOT copy `flutter create`'s other generated files
(`lib/main.dart`, `test/widget_test.dart`, `.idea/`, `.metadata`, `README.md`, `*.iml`) since those either
duplicate or would clobber the project's real, hand-written, already-tested source.

Customized `web/index.html`'s `<title>`/description and `web/manifest.json`'s `name`/`theme_color` to match
the app's real identity ("IoTGuard Auditor", dark theme `#0F172A`) rather than leaving Flutter's default
placeholder text ("A new Flutter project" / `auditor_web` / Flutter's default blue `#0175C2`).

Verified the fix directly: `docker build -t auditor-web-test . --provenance=false` now completes with
`✓ Built build/web`; running the built image and curling it returns `200` with `<title>IoTGuard Auditor</title>`
in the response body.

## How to prevent it next time
When a plan decides to hand-write source files instead of running a framework's official scaffolding tool
(here: `flutter create`, elsewhere: `npm init`/`cargo new`/etc.), explicitly account for every artifact that
tool would have produced, not just the ones the immediate test suite happens to exercise. `flutter test` and
`flutter build web` have different minimum-file requirements — passing the former is not evidence the latter
will work. This is the same class of gap as [014](014-record-evidence-sequence-collision-after-api-migration.md) (a design change tested by one code path but not
verified against a different, non-obviously-related one) — Task 17's implementer caught it the same
responsible way: reproduced the failure in isolation, diagnosed the root cause precisely (via a scratchpad
`flutter create` + rebuild trial), and reported it rather than guessing a fix outside their declared scope.

## References
None external — diagnosed directly by the Task 17 implementer's scratchpad reproduction, confirmed and fixed
by the controller.
