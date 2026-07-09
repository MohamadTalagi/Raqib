# Handoff — Read This First in a New Chat

> **RESOLVED (2026-07-09, later the same day):** the owner decided to abandon Flutter
> Web for the dashboard rather than keep iterating on it (option explicitly raised in
> §6 point 5 below). `lab/auditor/web/` is now a React + Tailwind v4 + Vite app. The
> root-cause analysis below is kept as-is for the historical record — same lesson
> (bundle fonts for real, get a design system before coding, verify visually with a
> real browser/screenshot, not just `analyze`/`test`) was applied to the rebuild. See
> `CLAUDE.md` §0 and §8 (2026-07-09 entry) for what shipped.

**Written:** 2026-07-09
**Why this file exists:** the owner is unhappy with the dashboard UI ("AI slop") after
waiting on it. This file exists so a fresh Claude Code session doesn't have to
re-derive project state from scratch, and goes straight at fixing the actual problem
instead of re-polishing the same broken approach.

**Read this, then read `CLAUDE.md` at the repo root** for full history/decisions. This
file is the short version + the specific UI problem and how to actually fix it.

---

## 1. What this project is

IoTGuard: an NCA-aligned IoT security compliance lab + dashboard, built for a KAUST
Academy cybersecurity project. Full pipeline: simulated vulnerable/hardened IoT
devices in Docker → manual + automated security evidence collection → policy-as-code
verdict engine mapped to Saudi NCA (CGIoT-1:2024) controls → a web dashboard showing
it all.

## 2. What's actually solid (don't rebuild this)

Everything **except the dashboard's visual design** is in good shape:

- **Lab infrastructure** (`lab/docker-compose.yml`): 11 containers — 3 device
  profiles (insecure/partial/hardened), 2 MQTT brokers, telnet-sim, traffic-capture,
  auditor-database (Postgres), auditor-api (FastAPI), auditor-web (Flutter), on a
  2-network topology (`audit-network` / `internal-network`).
- **`auditor-api`** (`lab/auditor/api/main.py`): FastAPI, full CRUD for evidence/
  verdicts/controls/devices/summary, CORS enabled, path-traversal-safe. Works, tested.
- **`policies/engine/`**: deterministic Python policy engine (no eval/exec), 5 NCA
  controls mapped to real CGIoT-1:2024 sources, verdict generation verified for real
  against evidence collected on the physical build PC.
- **45+ tests passing** across schema, policy engine, controls, firmware analysis,
  evidence recording, the FastAPI endpoints, and Flutter widget tests.
- **17 real errors hit and documented** in `docs/errors/001`–`017-*.md` — genuinely
  useful engineering record, keep this pattern going.
- Deployed and manually verified working on the physical build PC (Tailscale-reachable
  via ssh-mcp, host `OSRA-PC2025-V2`).

**None of this needs redoing.** The problem is scoped entirely to
`lab/auditor/web/` — the Flutter dashboard's visual layer.

## 3. The actual problem: why the dashboard looks like "AI slop"

I (the prior session) did a "full visual redesign" pass and it still reads as
generic. Root causes, concretely:

1. **Custom fonts were referenced but never bundled.** `lib/theme.dart:72` sets
   `fontFamily: 'Inter'` and defines `kMonospaceFontFamily = 'JetBrains Mono'`
   (`lib/theme.dart:84`), but `pubspec.yaml` has **no `fonts:` section at all** and
   there's no `assets/fonts/` directory. Flutter web silently falls back to the
   default system font. Typography is one of the highest-leverage things for making
   an app look designed vs. generic, and it was completely missing — this alone
   explains a lot of the "looks like a Bootstrap template" feeling.
2. **No real design process happened before implementation.** I went straight from
   "enhance the UI" to writing Dart code. I never generated mockups, never used the
   `ui-ux-pro-max` skill's design-system search, never asked for approval on a
   direction (color palette / layout pattern / style) before building it. The result
   is generically-competent Material Design defaults (dark theme, rounded cards,
   Material icons) with no distinctive point of view — exactly the "AI slop" pattern.
3. **No visual verification loop.** I checked `flutter analyze` (clean) and
   `flutter test` (11/11 pass) and declared it done. Those check code correctness,
   not whether it looks good. I never took a screenshot, never ran it past a design
   critic, never looked at it in a real browser myself before shipping it. The CORS
   bug earlier in this project was caught the same way — by the owner opening a real
   browser, not by me verifying with curl. Same blind spot, different layer.
4. **Material Design out of the box always looks like "an admin dashboard
   template."** Standard `Card`/`NavigationRail`/Material icons, even with a custom
   dark palette, converge on the same look every LLM produces by default. Breaking
   out of that requires either (a) a genuinely custom design system (real typography,
   custom iconography or an icon set with personality, unusual layout choices,
   micro-interactions) or (b) accepting Material's look and leaning hard into a
   specific, opinionated theme (not just "dark mode + rounded corners + one accent
   color," which is what shipped).

## 4. Where the code lives

- `lab/auditor/web/lib/theme.dart` — design tokens (colors, spacing, radii)
- `lab/auditor/web/lib/widgets/common.dart` — shared widgets (ScreenHeader,
  StatusChip, SkeletonList, ErrorState, EmptyState)
- `lab/auditor/web/lib/main.dart` — app shell, sidebar nav
- `lab/auditor/web/lib/screens/{overview,devices,evidence,verdicts}_screen.dart` —
  the 4 dashboard screens
- `lab/auditor/web/pubspec.yaml` — dependencies (missing font declarations, see §3.1)
- `lab/auditor/web/test/` — widget tests (11 passing, keep them green through any
  redesign)

Branch: `worktree-phase-6-8-implementation`, worktree at
`.claude/worktrees/phase-6-8-implementation`. Everything is committed and pushed to
`origin/worktree-phase-6-8-implementation` (latest: `0e0c70e`). Nothing is lost —
the redesign attempt is just not good enough, not broken.

## 5. How to run it

**Locally (no Flutter SDK installed anywhere in this environment — use Docker):**
```bash
docker run --rm -v "$(pwd)/lab/auditor/web":/app -w /app ghcr.io/cirruslabs/flutter:stable \
  sh -c "flutter pub get && flutter run -d web-server --web-port 8080"
```

**On the physical PC** (already running, via ssh-mcp `mcp__ssh-mcp__exec`):
```powershell
cd C:\Users\osama\Projects\kaust-iot-security-lab\lab
git pull
docker compose build auditor-web --provenance=false
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate auditor-web
```
Then open `http://localhost:8080` on the PC (or wherever it's port-forwarded).
**Important:** Flutter web ships a service worker that aggressively caches — after
any redeploy, hard-refresh (`Ctrl+Shift+R`) or check in an incognito window, or you
will see the old build and think the deploy failed.

## 6. Recommended plan for the next session

Don't just "try again" the same way. Do this instead, in order:

1. **Fix the font bug first regardless of anything else.** Bundle actual Inter +
   JetBrains Mono font files under `lab/auditor/web/assets/fonts/`, declare them in
   `pubspec.yaml`'s `flutter.fonts:` section. This alone will materially change how
   it looks and is a 15-minute fix.
2. **Before writing any more Dart: use the `ui-ux-pro-max` skill.** Run its
   `--design-system` search for something like "security compliance dashboard admin
   B2B" and get real recommendations (style, palette, typography pairing) instead of
   default dark-mode-plus-teal-accent.
3. **Get the owner to approve a direction before implementation.** Use the
   `superpowers:brainstorming` skill's visual companion (browser-based mockup tool)
   to show 2-3 real layout/style directions and get a thumbs-up on ONE before
   touching `lib/screens/`. This is the step that got skipped last time.
4. **Verify visually before declaring done, not just `flutter analyze`/`flutter
   test`.** Take an actual screenshot (Playwright MCP tools are available —
   `mcp__plugin_playwright_playwright__browser_take_screenshot` after navigating to
   `localhost:8080`) and either show it to the owner or run it through the
   `ui-ux-designer` subagent for a critique pass before calling it finished.
5. Consider whether a full Flutter rebuild of the visual layer is worth it vs.
   whether the owner would rather see this dashboard done in a stack that's easier
   to make look polished quickly (e.g., a static HTML/Tailwind or a shadcn/React
   dashboard) — worth explicitly asking rather than assuming Flutter Web is locked
   in, since the original "no frontend needed for the sprint, Flutter Web deferred
   to the full platform" decision (see `CLAUDE.md` §9) was made before this
   dashboard existed at all.

## 7. Still outstanding (unrelated to the UI complaint)

- Final whole-branch code review (opus-tier reviewer comparing this branch against
  `main`) has not run yet.
- `finishing-a-development-branch` skill (merge/PR/keep/discard decision) has not
  been invoked — the branch is still just sitting on
  `worktree-phase-6-8-implementation`, pushed but not merged.
- `.superpowers/sdd/progress.md` needs Task 20 logged as complete (gitignored, local
  ledger only, not committed).
