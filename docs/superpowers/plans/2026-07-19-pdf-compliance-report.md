# Per-Device PDF Compliance Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a downloadable, print-quality per-device assessment PDF generated server-side from the database and the NCA control definitions.

**Architecture:** A new `report.py` module splits into a **pure data function** (`build_report_model`, no rendering, fully testable without WeasyPrint) and a **render step** (Jinja2 template + paged-media CSS → WeasyPrint → PDF bytes). `main.py` gains one route. The document is deliberately light-themed, not a copy of the dark dashboard.

**Tech Stack:** FastAPI · WeasyPrint · Jinja2 · PostgreSQL · pytest · React (one button)

**Spec:** `docs/superpowers/specs/2026-07-19-pdf-compliance-report-design.md`

## Global Constraints

- **No LLM-generated narrative anywhere.** Every sentence is a fixed label, a database value, or text copied verbatim from a control YAML. A generated executive paragraph would contradict the report's own determinism claim.
- **IoTGuard branding only.** The line "Assessed against NCA CGIoT-1:2024" plus per-control `framework §reference` and clause text. **No NCA emblem** — the report states pass/fail verdicts and must not imply it was issued by the regulator.
- **The report is a light document** (near-black text on white), not the dashboard's dark theme.
- **Status is never colour alone** — `PASS` / `FAIL` / `PARTIAL` / `INCONCLUSIVE` always render as the word.
- **Provenance table, no raw-output appendix.** Raw output is cited by `raw_output_path` and SHA-256, never embedded.
- Unset inventory fields render **"Not recorded"**; a null `published_port` renders **"not browser-reachable"**.
- A verdict whose control YAML is missing still renders from stored data, marked incomplete. **Never drop a verdict** — that would silently remove a FAIL from a compliance document.
- Python: 4-space indent, type hints on new functions. No emojis.
- `main.py` stays a single file (owner decision). New concerns go in new modules.
- API suite baseline is **75 passing** and must not drop.

### How to run the API suite

Both env vars are required or it cannot collect — `main.py` hardcodes container paths:

```bash
cd lab/auditor/api
ROOT="C:/Users/cours/Desktop/Kaust IoT Project/.claude/worktrees/device-registration"
PYTHONPATH="$ROOT" CONTROLS_DIR="$ROOT/policies/controls" python -m pytest --no-header -q
```

Docker is running locally; the suite provisions its own Postgres on port 55432.

---

## File Structure

**Created:**
- `lab/auditor/api/report.py` — `build_report_model` (pure) + `render_report_pdf`
- `lab/auditor/api/test_report_model.py` — model tests, no WeasyPrint needed
- `lab/auditor/api/test_report_route.py` — route tests
- `lab/auditor/api/templates/device_report.html` — Jinja2 template, structure only
- `lab/auditor/api/templates/report.css` — paged-media stylesheet, all layout
- `lab/auditor/api/assets/fonts/` — vendored font faces

**Modified:**
- `lab/auditor/api/requirements.txt` — `weasyprint`, `jinja2`
- `lab/auditor/api/Dockerfile` — system libraries for WeasyPrint
- `lab/auditor/api/main.py` — one route, `GET /devices/{device_id}/report.pdf`
- `lab/auditor/web/src/lib/api.ts` — report URL helper
- `lab/auditor/web/src/pages/DeviceDetailPage.tsx` — "Download report" button

---

### Task 1: Dependencies, fonts, and a render smoke test

This task exists to de-risk the two unknowns before any report logic is written: whether WeasyPrint installs cleanly in this image, and which font format it actually accepts.

**Files:**
- Modify: `lab/auditor/api/requirements.txt`
- Modify: `lab/auditor/api/Dockerfile`
- Create: `lab/auditor/api/assets/fonts/` (vendored font files)
- Create: `lab/auditor/api/test_report_smoke.py`

**Interfaces:**
- Consumes: nothing
- Produces: a working WeasyPrint install; `assets/fonts/` containing font files whose exact filenames later tasks reference in `@font-face`

- [ ] **Step 1: Add the Python dependencies**

Append to `lab/auditor/api/requirements.txt`:

```
weasyprint==63.1
jinja2==3.1.5
```

- [ ] **Step 2: Add WeasyPrint's system libraries to the Dockerfile**

WeasyPrint renders through pango/cairo, which are not in `python:3.12-slim`. Replace `lab/auditor/api/Dockerfile` with:

```dockerfile
FROM python:3.12-slim
WORKDIR /app

# WeasyPrint renders via pango/cairo; python:slim ships neither.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi8 \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 3: Resolve the font format — do NOT assume**

The spec flags this explicitly. `@fontsource` (used by the web app) ships **`.woff` / `.woff2` only, no `.ttf`**, so the files cannot simply be copied from `node_modules`.

Determine what this WeasyPrint version accepts:

```bash
cd lab/auditor/api
python -c "import weasyprint; print(weasyprint.__version__)"
```

Then obtain three faces — **Inter Regular**, **Inter SemiBold**, **JetBrains Mono Regular** — and place them in `lab/auditor/api/assets/fonts/`. Prefer upstream `.ttf` releases (Inter: github.com/rsms/inter; JetBrains Mono: github.com/JetBrains/JetBrainsMono), because fontconfig handles TTF/OTF most reliably. If you use the `@fontsource` `.woff2` files instead, you must prove they render in Step 5 before proceeding.

Record in your report the exact filenames you placed and where they came from. Later tasks reference these filenames in `@font-face` — they are an interface.

- [ ] **Step 4: Write the smoke test**

Create `lab/auditor/api/test_report_smoke.py`:

```python
"""Proves WeasyPrint renders and the vendored fonts carry the glyphs we need.

Skipped when WeasyPrint is not installed locally, following the same pattern
policies/engine/test_seed_devices.py uses for an absent database.
"""
from pathlib import Path

import pytest

weasyprint = pytest.importorskip("weasyprint")

FONT_DIR = Path(__file__).parent / "assets" / "fonts"


def test_font_files_are_vendored():
    files = list(FONT_DIR.glob("*"))
    assert files, f"no font files found in {FONT_DIR}"


def test_weasyprint_renders_a_pdf():
    html = weasyprint.HTML(string="<html><body><p>hello</p></body></html>")
    pdf = html.write_pdf()
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 500


def test_rendered_pdf_is_not_empty_for_our_special_characters():
    # The real data contains section signs in NCA references and em-dashes in
    # display names ("Smart Camera — Insecure"), plus 64-char SHA-256 strings.
    # A missing glyph renders as a blank box in exactly the place a reader looks.
    html = weasyprint.HTML(
        string="<html><body><p>CGIoT-1:2024 §2-2-2 — Smart Camera</p>"
        "<p>7421af31aecc115c92498182563413bdb941aed43c90ff7d528544d52945ed61</p>"
        "</body></html>"
    )
    pdf = html.write_pdf()
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 500
```

- [ ] **Step 5: Run the smoke test and visually confirm the glyphs**

```bash
cd lab/auditor/api
python -m pytest test_report_smoke.py -v
```

Expected: 3 passed (or skipped if WeasyPrint isn't installed locally — if skipped, say so plainly in your report).

Then render a real file and **open it**, because a passing byte-length assertion does not tell you whether `§` rendered or came out as a blank box:

```bash
python -c "
import weasyprint
from pathlib import Path
fonts = Path('assets/fonts').resolve().as_uri()
css = '@font-face{font-family:Inter;src:url(%s/<YOUR-INTER-FILE>)} body{font-family:Inter}' % fonts
weasyprint.HTML(string='<p>CGIoT-1:2024 §2-2-2 — Smart Camera</p>').write_pdf('/tmp/fonttest.pdf', stylesheets=[weasyprint.CSS(string=css)])
print('wrote /tmp/fonttest.pdf')
"
```

Substitute your actual font filename. Open the PDF and confirm `§` and `—` appear as characters, not boxes. Report what you saw.

- [ ] **Step 6: Confirm the API suite still passes**

```bash
cd lab/auditor/api
ROOT="C:/Users/cours/Desktop/Kaust IoT Project/.claude/worktrees/device-registration"
PYTHONPATH="$ROOT" CONTROLS_DIR="$ROOT/policies/controls" python -m pytest --no-header -q
```

Expected: **75 passed** plus your new smoke tests.

- [ ] **Step 7: Commit**

```bash
git add lab/auditor/api/requirements.txt lab/auditor/api/Dockerfile lab/auditor/api/assets lab/auditor/api/test_report_smoke.py
git commit -m "chore(api): add WeasyPrint, system deps and vendored report fonts

python:slim ships neither pango nor cairo, and @fontsource provides no TTF,
so the report fonts are vendored explicitly."
```

---

### Task 2: The report data model

The pure half. No WeasyPrint, no HTML — just the dict the template will consume.

**Files:**
- Create: `lab/auditor/api/report.py`
- Create: `lab/auditor/api/test_report_model.py`

**Interfaces:**
- Consumes: `db.get_connection`; `main._load_all_controls()` is NOT reused (avoid a circular import — see Step 3)
- Produces:
  - `build_report_model(conn, device_id: str) -> dict | None` — returns `None` when the device does not exist
  - Model shape (later tasks depend on these exact keys):
    ```
    {
      "device": {device_id, display_name, description, tier, host, vendor, model,
                 location, owner, notes, source, created_at, updated_at},
      "services": [{service_type, port, published_port, enabled}],
      "controls": [{control_id, title, severity, framework, reference, clause,
                    status, reason, verdict_id, timestamp, remediation,
                    control_found: bool}],
      "counts": {"PASS": int, "FAIL": int, "PARTIAL": int, "INCONCLUSIVE": int},
      "evidence": [{evidence_id, test_id, tool, tool_version, command, timestamp,
                    finding, confidence, raw_output_path, sha256}],
      "generated_at": str,
    }
    ```

> **Note:** the existing `GET /devices/{id}` endpoint's evidence rows carry only `finding`, `tool` and `confidence` — **not** `tool_version`, `command`, `sha256` or `raw_output_path`. The provenance table needs those, so this module runs its own query rather than reusing that endpoint.

- [ ] **Step 1: Write the failing tests**

Create `lab/auditor/api/test_report_model.py`:

```python
import psycopg
import pytest

from report import build_report_model


def _register_device(conn, device_id="report-cam"):
    conn.execute(
        """
        INSERT INTO devices (device_id, display_name, description, tier, host,
                             vendor, model, location, owner, notes, source)
        VALUES (%s, 'Report Cam', 'A camera under test.', 'insecure',
                'device-insecure', 'AcmeCam', NULL, 'Bench 2', NULL, NULL, 'manual')
        """,
        (device_id,),
    )
    conn.execute(
        """
        INSERT INTO device_services (device_id, service_type, port, published_port)
        VALUES (%s, 'http', 80, 8081), (%s, 'mqtt', 1883, NULL)
        """,
        (device_id, device_id),
    )


def _add_evidence(conn, device_id="report-cam"):
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES ('EV-REPORT-1', %s, 'TEST-AUTH-DEFAULT-CREDS', 'curl', '8.5.0',
                'curl -s -X POST http://device-insecure/login', now(),
                'Default creds admin/admin accepted', '{}'::jsonb,
                'document-store/raw/EV-REPORT-1.txt', 'high',
                '7421af31aecc115c92498182563413bdb941aed43c90ff7d528544d52945ed61')
        """,
        (device_id,),
    )


def _add_verdict(conn, control_id, status, device_id="report-cam", verdict_id="VD-R-1"):
    conn.execute(
        """
        INSERT INTO verdicts (verdict_id, control_id, device_id, status, severity,
                              evidence_ids, reason, saudi_source, remediation, timestamp)
        VALUES (%s, %s, %s, %s, 'high', '["EV-REPORT-1"]'::jsonb,
                'observations.default_creds equals True', '{}'::jsonb,
                'stored remediation', now())
        """,
        (verdict_id, control_id, device_id, status),
    )


def test_returns_none_for_unknown_device(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        assert build_report_model(conn, "does-not-exist") is None
    finally:
        conn.close()


def test_device_and_services_are_populated(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    assert model["device"]["display_name"] == "Report Cam"
    assert model["device"]["vendor"] == "AcmeCam"
    assert model["device"]["model"] is None
    assert len(model["services"]) == 2
    mqtt = next(s for s in model["services"] if s["service_type"] == "mqtt")
    assert mqtt["published_port"] is None


def test_device_with_no_evidence_returns_empty_lists_not_an_error(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    assert model["evidence"] == []
    assert model["controls"] == []
    assert model["counts"] == {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "INCONCLUSIVE": 0}


def test_provenance_fields_survive_byte_for_byte(postgres_url):
    # This is the reproducibility claim: a reader must be able to re-run the
    # command and check the hash. Assert it explicitly rather than assuming.
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_evidence(conn)
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    row = model["evidence"][0]
    assert row["evidence_id"] == "EV-REPORT-1"
    assert row["tool"] == "curl"
    assert row["tool_version"] == "8.5.0"
    assert row["command"] == "curl -s -X POST http://device-insecure/login"
    assert row["sha256"] == (
        "7421af31aecc115c92498182563413bdb941aed43c90ff7d528544d52945ed61"
    )
    assert row["raw_output_path"] == "document-store/raw/EV-REPORT-1.txt"
    assert row["confidence"] == "high"


def test_verdict_joins_control_metadata_from_yaml(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_verdict(conn, "SA-IOT-002", "FAIL")
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    control = model["controls"][0]
    assert control["control_id"] == "SA-IOT-002"
    assert control["control_found"] is True
    assert control["title"] == "No default or hard-coded credentials"
    assert control["framework"] == "CGIoT-1:2024"
    assert control["reference"] == "2-2-2"
    assert "default and hard-coded passwords" in control["clause"]
    assert control["status"] == "FAIL"
    assert control["reason"] == "observations.default_creds equals True"
    assert model["counts"]["FAIL"] == 1


def test_verdict_with_missing_control_yaml_still_appears(postgres_url):
    # Verdicts are database rows; controls are files. They can drift. Dropping a
    # verdict whose control file vanished would silently remove a FAIL from a
    # compliance document - the dangerous failure.
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_verdict(conn, "SA-IOT-999", "FAIL")
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    control = model["controls"][0]
    assert control["control_id"] == "SA-IOT-999"
    assert control["control_found"] is False
    assert control["status"] == "FAIL"
    assert control["title"] is None
    assert control["clause"] is None
    assert model["counts"]["FAIL"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd lab/auditor/api
ROOT="C:/Users/cours/Desktop/Kaust IoT Project/.claude/worktrees/device-registration"
PYTHONPATH="$ROOT" CONTROLS_DIR="$ROOT/policies/controls" python -m pytest test_report_model.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'report'`

- [ ] **Step 3: Write the model builder**

Create `lab/auditor/api/report.py`:

```python
"""Builds and renders the per-device PDF assessment report.

Split deliberately in two: build_report_model() is a pure data function with no
rendering dependency, so report *content* can be tested without WeasyPrint and
without parsing a PDF. render_report_pdf() is the only part that needs the
renderer.

Nothing here generates narrative text. Every value is a database value or text
copied verbatim from a control YAML - a generated summary paragraph would
contradict the report's own determinism claim.
"""
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml

VERDICT_STATUSES = ("PASS", "FAIL", "PARTIAL", "INCONCLUSIVE")

# Read lazily rather than as a module-level constant so it reflects the
# environment at request time, matching how main.py resolves CONTROLS_DIR.
def _controls_dir() -> Path:
    return Path(os.environ.get("CONTROLS_DIR", "/work/policies/controls"))


def _load_control(control_id: str) -> dict | None:
    """Load one control YAML, or None if the file is gone.

    Controls are files and verdicts are database rows, so they can drift.
    """
    path = _controls_dir() / f"{control_id}.yaml"
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _first_saudi_source(control: dict) -> dict:
    sources = control.get("saudi_source") or []
    return sources[0] if sources else {}


def build_report_model(conn, device_id: str) -> dict | None:
    """Assemble everything the report template needs. None if device is unknown."""
    device_row = conn.execute(
        """
        SELECT device_id, display_name, description, tier, host, vendor, model,
               location, owner, notes, source, created_at, updated_at
        FROM devices WHERE device_id = %s
        """,
        (device_id,),
    ).fetchone()
    if device_row is None:
        return None

    device_keys = (
        "device_id", "display_name", "description", "tier", "host", "vendor",
        "model", "location", "owner", "notes", "source", "created_at", "updated_at",
    )
    device = dict(zip(device_keys, device_row))
    device["created_at"] = device["created_at"].isoformat()
    device["updated_at"] = device["updated_at"].isoformat()

    service_rows = conn.execute(
        """
        SELECT service_type, port, published_port, enabled
        FROM device_services WHERE device_id = %s ORDER BY id
        """,
        (device_id,),
    ).fetchall()
    services = [
        {"service_type": r[0], "port": r[1], "published_port": r[2], "enabled": r[3]}
        for r in service_rows
    ]

    verdict_rows = conn.execute(
        """
        SELECT verdict_id, control_id, status, severity, reason, timestamp
        FROM verdicts WHERE device_id = %s ORDER BY control_id
        """,
        (device_id,),
    ).fetchall()

    controls = []
    counts = {status: 0 for status in VERDICT_STATUSES}
    for verdict_id, control_id, status, severity, reason, timestamp in verdict_rows:
        control = _load_control(control_id)
        source = _first_saudi_source(control) if control else {}
        controls.append(
            {
                "control_id": control_id,
                "title": control.get("title") if control else None,
                "severity": severity,
                "framework": source.get("framework"),
                "reference": source.get("reference"),
                "clause": source.get("clause"),
                "remediation": control.get("remediation") if control else None,
                "status": status,
                "reason": reason,
                "verdict_id": verdict_id,
                "timestamp": timestamp.isoformat(),
                "control_found": control is not None,
            }
        )
        if status in counts:
            counts[status] += 1

    evidence_rows = conn.execute(
        """
        SELECT evidence_id, test_id, tool, tool_version, command, timestamp,
               finding, confidence, raw_output_path, sha256
        FROM evidence WHERE device_id = %s ORDER BY timestamp
        """,
        (device_id,),
    ).fetchall()
    evidence = [
        {
            "evidence_id": r[0], "test_id": r[1], "tool": r[2], "tool_version": r[3],
            "command": r[4], "timestamp": r[5].isoformat(), "finding": r[6],
            "confidence": r[7], "raw_output_path": r[8], "sha256": r[9],
        }
        for r in evidence_rows
    ]

    return {
        "device": device,
        "services": services,
        "controls": controls,
        "counts": counts,
        "evidence": evidence,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd lab/auditor/api
ROOT="C:/Users/cours/Desktop/Kaust IoT Project/.claude/worktrees/device-registration"
PYTHONPATH="$ROOT" CONTROLS_DIR="$ROOT/policies/controls" python -m pytest test_report_model.py -v
```

Expected: PASS, 6 tests.

- [ ] **Step 5: Run the full suite**

Same command without the filename. Expected: **75 + your new tests**, none failing.

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/api/report.py lab/auditor/api/test_report_model.py
git commit -m "feat(api): add the per-device report data model

Pure data function, no renderer dependency, so report content is testable
without parsing a PDF. A verdict whose control YAML is missing still renders,
marked incomplete - dropping it would remove a FAIL from a compliance document."
```

---

### Task 3: Template and stylesheet

**Files:**
- Create: `lab/auditor/api/templates/device_report.html`
- Create: `lab/auditor/api/templates/report.css`
- Modify: `lab/auditor/api/report.py` (add `render_report_pdf`)
- Modify: `lab/auditor/api/test_report_smoke.py` (add a real-template render test)

**Interfaces:**
- Consumes: `build_report_model`'s dict (Task 2), the font filenames vendored in Task 1
- Produces: `render_report_pdf(model: dict) -> bytes`

- [ ] **Step 1: Write the stylesheet**

Create `lab/auditor/api/templates/report.css`. **Replace the three `src:` filenames with the actual files you vendored in Task 1.**

```css
/* Light document on purpose: the dashboard's dark theme burns ink and reads
   badly on paper. Brand identity carries through type and the amber accent. */

@font-face { font-family: "Inter"; font-weight: 400; src: url("../assets/fonts/Inter-Regular.ttf"); }
@font-face { font-family: "Inter"; font-weight: 600; src: url("../assets/fonts/Inter-SemiBold.ttf"); }
@font-face { font-family: "JetBrains Mono"; font-weight: 400; src: url("../assets/fonts/JetBrainsMono-Regular.ttf"); }

:root {
  --ink: #111827;
  --muted: #6b7280;
  --rule: #d1d5db;
  --accent: #b45309;
  --pass: #15803d;
  --fail: #b91c1c;
  --partial: #a16207;
  --inconclusive: #4b5563;
}

@page {
  size: A4;
  margin: 18mm 18mm 20mm 18mm;
  @top-left  { content: string(devicename); font-family: "Inter"; font-size: 8pt; color: #6b7280; }
  @top-right { content: "Device Security Assessment"; font-family: "Inter"; font-size: 8pt; color: #6b7280; }
  @bottom-left  { content: "Generated by IoTGuard"; font-family: "Inter"; font-size: 8pt; color: #6b7280; }
  @bottom-right { content: "page " counter(page) " of " counter(pages); font-family: "Inter"; font-size: 8pt; color: #6b7280; }
}

body { font-family: "Inter"; font-size: 9pt; color: var(--ink); line-height: 1.45; }
code, .mono { font-family: "JetBrains Mono"; }

h1 { font-size: 16pt; font-weight: 600; margin: 0 0 2mm 0; string-set: devicename content(); }
h2 { font-size: 11pt; font-weight: 600; margin: 7mm 0 2mm 0;
     padding-bottom: 1mm; border-bottom: 1px solid var(--accent);
     break-after: avoid; }

.subtitle { color: var(--muted); margin: 0 0 1mm 0; }
.cite { color: var(--muted); font-size: 8pt; }

.grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 3mm 6mm; }
.label { color: var(--muted); font-size: 7.5pt; text-transform: uppercase; letter-spacing: 0.04em; }
.value { font-size: 9pt; }
.value.empty { color: var(--muted); font-style: italic; }

table { width: 100%; border-collapse: collapse; margin-top: 2mm; }
th { text-align: left; font-size: 7.5pt; text-transform: uppercase; letter-spacing: 0.04em;
     color: var(--muted); font-weight: 600; border-bottom: 1px solid var(--rule);
     padding: 1.5mm 2mm 1.5mm 0; }
td { padding: 1.8mm 2mm 1.8mm 0; border-bottom: 1px solid #eef0f3; vertical-align: top; }

/* The dense one. Long commands wrap instead of overflowing; a 64-char hash
   wraps rather than shrinking to unreadability. */
.provenance td, .provenance th { font-size: 7.5pt; }
.provenance .mono { overflow-wrap: anywhere; word-break: break-all; }

/* Status is never colour alone - the word always renders, because this will be
   printed in greyscale and read by colourblind people. */
.status { font-weight: 600; }
.status-PASS { color: var(--pass); }
.status-FAIL { color: var(--fail); }
.status-PARTIAL { color: var(--partial); }
.status-INCONCLUSIVE { color: var(--inconclusive); }

/* Keep a control's clause, verdict and remediation together. Splitting these
   across a page is the most common reason a generated PDF looks amateur. */
.finding { break-inside: avoid; padding: 3mm 0; border-bottom: 1px solid #eef0f3; }
.finding .clause { font-style: italic; color: #374151; margin: 1mm 0; }
.finding .reason { font-family: "JetBrains Mono"; font-size: 8pt; }
.finding .remediation { margin-top: 1mm; }
.incomplete { color: var(--muted); font-style: italic; }

.empty-state { color: var(--muted); font-style: italic; padding: 3mm 0; }
```

- [ ] **Step 2: Write the template**

Create `lab/auditor/api/templates/device_report.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Device Security Assessment — {{ device.display_name }}</title></head>
<body>

<h1>{{ device.display_name }}</h1>
<p class="subtitle mono">{{ device.device_id }} &middot; {{ device.tier }} &middot; {{ device.host }}</p>
<p class="cite">Assessed against NCA CGIoT-1:2024 &middot; generated {{ generated_at }}</p>

<h2>1. Device profile</h2>
<div class="grid">
  {% for label, value in [
      ("Vendor", device.vendor), ("Model", device.model), ("Location", device.location),
      ("Owner", device.owner), ("Notes", device.notes), ("Source", device.source)] %}
  <div>
    <div class="label">{{ label }}</div>
    {% if value %}<div class="value">{{ value }}</div>
    {% else %}<div class="value empty">Not recorded</div>{% endif %}
  </div>
  {% endfor %}
</div>
{% if device.description %}<p class="value" style="margin-top:3mm">{{ device.description }}</p>{% endif %}

<h2>2. Exposed services</h2>
<p class="cite">Internal port is what the auditor targets inside the lab network. Published port is what a browser on the host reaches.</p>
{% if services %}
<table>
  <thead><tr><th>Service</th><th>Internal port</th><th>Published port</th><th>Enabled</th></tr></thead>
  <tbody>
  {% for s in services %}
    <tr>
      <td class="mono">{{ s.service_type }}</td>
      <td class="mono">{{ s.port }}</td>
      <td class="mono">{% if s.published_port %}{{ s.published_port }}{% else %}<span class="empty">not browser-reachable</span>{% endif %}</td>
      <td>{{ "yes" if s.enabled else "no" }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}<p class="empty-state">No services recorded for this device.</p>{% endif %}

<h2>3. Compliance summary</h2>
{% if controls %}
<p class="cite">
  {{ counts.PASS }} pass &middot; {{ counts.FAIL }} fail &middot;
  {{ counts.PARTIAL }} partial &middot; {{ counts.INCONCLUSIVE }} inconclusive
</p>
<table>
  <thead><tr><th>Control</th><th>Title</th><th>Severity</th><th>Reference</th><th>Verdict</th></tr></thead>
  <tbody>
  {% for c in controls %}
    <tr>
      <td class="mono">{{ c.control_id }}</td>
      <td>{% if c.title %}{{ c.title }}{% else %}<span class="incomplete">control definition unavailable</span>{% endif %}</td>
      <td>{{ c.severity }}</td>
      <td class="mono">{% if c.framework %}{{ c.framework }} &sect;{{ c.reference }}{% else %}&mdash;{% endif %}</td>
      <td class="status status-{{ c.status }}">{{ c.status }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}<p class="empty-state">No compliance verdicts recorded for this device.</p>{% endif %}

<h2>4. Findings</h2>
{% if controls %}
  {% for c in controls %}
  <div class="finding">
    <div><span class="mono">{{ c.control_id }}</span> &mdash;
      <span class="status status-{{ c.status }}">{{ c.status }}</span>
      {% if c.title %}&middot; {{ c.title }}{% endif %}
    </div>
    {% if c.clause %}<div class="clause">&ldquo;{{ c.clause }}&rdquo;</div>
    {% else %}<div class="clause incomplete">Control definition unavailable; verdict shown from stored record.</div>{% endif %}
    <div class="reason">{{ c.reason }}</div>
    {% if c.remediation %}<div class="remediation"><strong>Remediation.</strong> {{ c.remediation }}</div>{% endif %}
  </div>
  {% endfor %}
{% else %}<p class="empty-state">No findings recorded for this device.</p>{% endif %}

<h2>5. Evidence provenance</h2>
{% if evidence %}
<p class="cite">Each record is reproducible from its command and verifiable against its SHA-256.</p>
<table class="provenance">
  <thead><tr><th>Evidence</th><th>Tool</th><th>Command</th><th>Finding</th><th>Confidence</th><th>SHA-256</th></tr></thead>
  <tbody>
  {% for e in evidence %}
    <tr>
      <td class="mono">{{ e.evidence_id }}<br><span class="cite">{{ e.timestamp }}</span></td>
      <td class="mono">{{ e.tool }}<br><span class="cite">{{ e.tool_version }}</span></td>
      <td class="mono">{{ e.command }}</td>
      <td>{{ e.finding }}</td>
      <td>{{ e.confidence }}</td>
      <td class="mono">{{ e.sha256 }}<br><span class="cite">{{ e.raw_output_path }}</span></td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}<p class="empty-state">No evidence recorded for this device.</p>{% endif %}

</body>
</html>
```

- [ ] **Step 3: Add the renderer to `report.py`**

Append to `lab/auditor/api/report.py`:

```python
TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_report_pdf(model: dict) -> bytes:
    """Render the report model to PDF bytes. This is the only WeasyPrint step."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from weasyprint import CSS, HTML
    from weasyprint.text.fonts import FontConfiguration

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    html = env.get_template("device_report.html").render(**model)

    # font_config MUST be passed to BOTH CSS() and write_pdf(), or WeasyPrint
    # silently ignores every @font-face rule and falls back to DejaVu Sans.
    # The fallback is invisible to the eye: DejaVu covers the section sign, the
    # em-dash and hex digits, and has distinct weights, so a rendered PDF looks
    # correct while using none of the vendored fonts. Verify with `pdffonts`,
    # never by looking.
    font_config = FontConfiguration()

    # base_url lets the stylesheet's relative ../assets/fonts/ paths resolve.
    return HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(
        stylesheets=[
            CSS(filename=str(TEMPLATE_DIR / "report.css"), font_config=font_config)
        ],
        font_config=font_config,
    )
```

Note the imports are function-local on purpose: `report.py` must stay importable for the model tests on a machine without WeasyPrint installed.

- [ ] **Step 4: Add a real-template render test**

Append to `lab/auditor/api/test_report_smoke.py`:

```python
def test_renders_the_real_template_end_to_end():
    from report import render_report_pdf

    model = {
        "device": {
            "device_id": "device-insecure", "display_name": "Smart Camera — Insecure",
            "description": "Default creds, plain HTTP.", "tier": "insecure",
            "host": "device-insecure", "vendor": "AcmeCam", "model": None,
            "location": None, "owner": None, "notes": None, "source": "seeded",
            "created_at": "2026-07-19T00:00:00+00:00",
            "updated_at": "2026-07-19T00:00:00+00:00",
        },
        "services": [
            {"service_type": "http", "port": 80, "published_port": 8081, "enabled": True},
            {"service_type": "mqtt", "port": 1883, "published_port": None, "enabled": True},
        ],
        "controls": [
            {
                "control_id": "SA-IOT-002", "title": "No default or hard-coded credentials",
                "severity": "high", "framework": "CGIoT-1:2024", "reference": "2-2-2",
                "clause": "Prevent the users from using default and hard-coded passwords.",
                "remediation": "Force a unique strong password on first boot.",
                "status": "FAIL", "reason": "observations.default_creds equals True",
                "verdict_id": "VD-1", "timestamp": "2026-07-08T08:58:44+00:00",
                "control_found": True,
            },
            {
                "control_id": "SA-IOT-999", "title": None, "severity": "high",
                "framework": None, "reference": None, "clause": None,
                "remediation": None, "status": "FAIL", "reason": "stored reason",
                "verdict_id": "VD-2", "timestamp": "2026-07-08T08:58:44+00:00",
                "control_found": False,
            },
        ],
        "counts": {"PASS": 0, "FAIL": 2, "PARTIAL": 0, "INCONCLUSIVE": 0},
        "evidence": [
            {
                "evidence_id": "EV-1", "test_id": "TEST-AUTH-DEFAULT-CREDS",
                "tool": "curl", "tool_version": "8.5.0",
                "command": "curl -s -X POST http://device-insecure/login",
                "timestamp": "2026-07-08T08:58:44+00:00",
                "finding": "Default creds admin/admin accepted", "confidence": "high",
                "raw_output_path": "document-store/raw/EV-1.txt",
                "sha256": "7421af31aecc115c92498182563413bdb941aed43c90ff7d528544d52945ed61",
            }
        ],
        "generated_at": "2026-07-19T12:00:00+00:00",
    }

    pdf = render_report_pdf(model)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 3000


def test_renders_a_device_with_no_evidence():
    from report import render_report_pdf

    pdf = render_report_pdf(
        {
            "device": {
                "device_id": "telnet-sim", "display_name": "Telnet Service Simulator",
                "description": "", "tier": "insecure", "host": "telnet-sim",
                "vendor": None, "model": None, "location": None, "owner": None,
                "notes": None, "source": "seeded",
                "created_at": "2026-07-19T00:00:00+00:00",
                "updated_at": "2026-07-19T00:00:00+00:00",
            },
            "services": [
                {"service_type": "telnet", "port": 23, "published_port": None, "enabled": True}
            ],
            "controls": [],
            "counts": {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "INCONCLUSIVE": 0},
            "evidence": [],
            "generated_at": "2026-07-19T12:00:00+00:00",
        }
    )
    assert pdf.startswith(b"%PDF-")
```

- [ ] **Step 5: Run the tests, then LOOK at the output**

```bash
cd lab/auditor/api
python -m pytest test_report_smoke.py -v
```

Expected: all pass.

Now render a file you can actually open. Make the test model reusable rather than
hand-copying it: extract the dict from
`test_renders_the_real_template_end_to_end` into a module-level constant
`SAMPLE_MODEL` in `test_report_smoke.py`, and have the test use it. Then:

```bash
cd lab/auditor/api
python -c "from pathlib import Path; from test_report_smoke import SAMPLE_MODEL; from report import render_report_pdf; Path('sample-report.pdf').write_bytes(render_report_pdf(SAMPLE_MODEL)); print('wrote sample-report.pdf')"
```

Open `sample-report.pdf`. Delete it before committing (or add it to
`.gitignore` — do not commit a generated artifact).

**Check specifically:** `§` and the em-dash in "Smart Camera — Insecure" render as
characters not boxes; the long command and the 64-char hash wrap inside their
columns instead of overflowing the page; the `SA-IOT-999` block shows "Control
definition unavailable" rather than blanks; nothing is orphaned across a page
break. Report what you saw — a passing byte-length assertion proves none of this.

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/api/templates lab/auditor/api/report.py lab/auditor/api/test_report_smoke.py
git commit -m "feat(api): add the report template and paged-media stylesheet

Light document rather than the dashboard's dark theme; status renders as a word
so it survives greyscale printing; findings use break-inside:avoid so a control's
clause never splits from its verdict."
```

---

### Task 4: The download route

**Files:**
- Modify: `lab/auditor/api/main.py`
- Create: `lab/auditor/api/test_report_route.py`

**Interfaces:**
- Consumes: `report.build_report_model`, `report.render_report_pdf`
- Produces: `GET /devices/{device_id}/report.pdf`

- [ ] **Step 1: Write the failing tests**

Create `lab/auditor/api/test_report_route.py`:

```python
import psycopg
import pytest


def _register(conn, device_id="route-cam"):
    conn.execute(
        """
        INSERT INTO devices (device_id, display_name, description, tier, host, source)
        VALUES (%s, 'Route Cam', '', 'insecure', 'device-insecure', 'manual')
        """,
        (device_id,),
    )
    conn.execute(
        """
        INSERT INTO device_services (device_id, service_type, port, published_port)
        VALUES (%s, 'http', 80, 8081)
        """,
        (device_id,),
    )
    conn.commit()


def test_unknown_device_returns_404(client):
    assert client.get("/devices/no-such-device/report.pdf").status_code == 404


def test_malformed_device_id_returns_400_with_field(client):
    response = client.get("/devices/Bad_Device/report.pdf")
    assert response.status_code == 400
    assert response.json()["field"] == "device_id"


def test_returns_a_pdf_with_a_download_filename(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    pytest.importorskip("weasyprint")
    response = client.get("/devices/route-cam/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert "iotguard-route-cam-" in disposition
    assert response.content.startswith(b"%PDF-")
```

Use the same `client(postgres_url, monkeypatch)` fixture the other route test files use — `db.py` reads `os.environ["DATABASE_URL"]` at call time, so a module-level `TestClient` fails.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd lab/auditor/api
ROOT="C:/Users/cours/Desktop/Kaust IoT Project/.claude/worktrees/device-registration"
PYTHONPATH="$ROOT" CONTROLS_DIR="$ROOT/policies/controls" python -m pytest test_report_route.py -v
```

Expected: FAIL — route returns 404 for every case because it does not exist.

- [ ] **Step 3: Add the route**

Add the import near the other imports in `lab/auditor/api/main.py`:

```python
from fastapi.responses import Response
from report import build_report_model, render_report_pdf
```

(`JSONResponse` is already imported; add `Response` to that import if it is on the same line.)

Then add the route. Place it **before** the existing `@app.get("/devices/{device_id}")` route so the more specific path is matched first:

```python
@app.get("/devices/{device_id}/report.pdf")
def get_device_report(device_id: str):
    # validate_device_id raises ValidationError, which the global handler turns
    # into a 400 {field, detail}. device_id is constrained to
    # ^[a-z0-9][a-z0-9-]{0,62}$, so it cannot inject quotes, slashes or newlines
    # into the Content-Disposition header below.
    validate_device_id(device_id)

    conn = get_connection()
    try:
        model = build_report_model(conn, device_id)
    finally:
        conn.close()

    if model is None:
        raise HTTPException(status_code=404, detail="device not found")

    pdf = render_report_pdf(model)
    filename = f"iotguard-{device_id}-{datetime.now(timezone.utc):%Y-%m-%d}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
```

`datetime` and `timezone` are already imported at the top of `main.py`.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd lab/auditor/api
ROOT="C:/Users/cours/Desktop/Kaust IoT Project/.claude/worktrees/device-registration"
PYTHONPATH="$ROOT" CONTROLS_DIR="$ROOT/policies/controls" python -m pytest test_report_route.py -v
```

Expected: PASS, 3 tests.

- [ ] **Step 5: Confirm route ordering did not break the existing detail route**

```bash
PYTHONPATH="$ROOT" CONTROLS_DIR="$ROOT/policies/controls" python -m pytest --no-header -q
```

Expected: **75 + all new tests**, none failing. If `test_devices_crud.py`'s detail tests fail, your route is shadowing `GET /devices/{device_id}` — check the ordering.

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/api/main.py lab/auditor/api/test_report_route.py
git commit -m "feat(api): add GET /devices/{id}/report.pdf

device_id is validated before use; its charset constraint is what makes it safe
to interpolate into the Content-Disposition filename."
```

---

### Task 5: Download button on the device detail page

**Files:**
- Modify: `lab/auditor/web/src/lib/api.ts`
- Modify: `lab/auditor/web/src/pages/DeviceDetailPage.tsx`
- Modify: `lab/auditor/web/src/pages/DeviceDetailPage.test.tsx`

**Interfaces:**
- Consumes: the route from Task 4
- Produces: `api.deviceReportUrl(deviceId: string): string`

- [ ] **Step 1: Write the failing test**

Append to `lab/auditor/web/src/pages/DeviceDetailPage.test.tsx`, inside the existing `describe`:

```typescript
  it("offers a download link to the device report", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL as never);
    renderPage();

    const link = await screen.findByRole("link", { name: /download report/i });
    expect(link).toHaveAttribute("href", expect.stringContaining("/devices/device-insecure/report.pdf"));
  });
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd lab/auditor/web
npm test -- --run DeviceDetailPage
```

Expected: FAIL — no link with that accessible name.

- [ ] **Step 3: Add the URL helper**

In `lab/auditor/web/src/lib/api.ts`, add to the exported `api` object:

```typescript
  deviceReportUrl: (deviceId: string): string =>
    `${API_BASE_URL}/devices/${encodeURIComponent(deviceId)}/report.pdf`,
```

This returns a URL rather than fetching, because the browser must perform the download itself so the `Content-Disposition` filename is honoured.

- [ ] **Step 4: Add the button**

In `lab/auditor/web/src/pages/DeviceDetailPage.tsx`, import `FileDown` from `lucide-react` and render an anchor in the page header block. Use the **exact token names the existing primary button uses** (`DevicesPage.tsx:50`) — `--color-brand` and `--color-brand-foreground`. Note `--color-accent` does **not** exist in `index.css`; using it would render an unstyled button:

```tsx
<a
  href={api.deviceReportUrl(device.device_id)}
  className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
>
  <FileDown className="h-4 w-4" />
  Download report
</a>
```

Use an `<a>`, not a `<button>` with an onClick — a plain link lets the browser handle the download and the `Content-Disposition` header naturally.

- [ ] **Step 5: Run tests and typecheck**

```bash
cd lab/auditor/web
npm test -- --run
npx tsc --noEmit
```

Expected: all tests pass (45 + your new one), `tsc` clean.

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/web/src/lib/api.ts lab/auditor/web/src/pages/DeviceDetailPage.tsx lab/auditor/web/src/pages/DeviceDetailPage.test.tsx
git commit -m "feat(web): add a download-report link to the device detail page"
```

---

### Task 6: Deploy and verify on the build PC

No new code. This is where you find out whether the document is actually good.

**Files:** none, unless verification finds a bug — then fix it and log the error under `docs/errors/` per the project convention.

- [ ] **Step 1: Push and pull**

```bash
git push
```

On the PC over ssh-mcp (PowerShell — use `;` not `&&`; note ssh-mcp has a hard 60-second timeout, so long builds must run detached via `Start-Process` and be polled):

```powershell
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull
```

- [ ] **Step 2: Rebuild `auditor-api` detached**

The image gains an `apt-get` layer, so this is slow. Do not run it synchronously.

```powershell
$lab="C:\Users\osama\Projects\kaust-iot-security-lab\lab"
Start-Process -FilePath "docker" -ArgumentList "compose","build","auditor-api" -WorkingDirectory $lab -RedirectStandardOutput "$env:TEMP\rep.log" -RedirectStandardError "$env:TEMP\rep.err" -NoNewWindow
```

Poll until the image is fresh:

```powershell
docker images --format "{{.Repository}} {{.CreatedSince}}" | Select-String "auditor-api"
```

If the build stalls pulling a base layer with zero bytes transferred for minutes, kill it and `docker pull` the base image directly first — buildkit has wedged this way before on this machine.

- [ ] **Step 3: Recreate and confirm the stack is healthy**

```powershell
cd C:\Users\osama\Projects\kaust-iot-security-lab\lab
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate auditor-api
Start-Sleep -Seconds 25
docker compose -f docker-compose.yml -f docker-compose.dev.yml ps --format "{{.Name}} {{.Status}}"
```

Expected: 11 services Up, none unhealthy.

- [ ] **Step 4: Confirm the audit record is untouched**

```powershell
curl.exe -s http://localhost:8000/summary
```

Expected exactly: `{"total_evidence":13,"total_verdicts":8,"verdicts_by_status":{"PASS":4,"FAIL":4,"PARTIAL":0,"INCONCLUSIVE":0}}`

This feature only reads, so any change here means something is wrong.

- [ ] **Step 5: Download three real reports**

```powershell
curl.exe -s -o "$env:TEMP\r-insecure.pdf" -w "insecure: %{http_code} %{size_download} bytes`n" http://localhost:8000/devices/device-insecure/report.pdf
curl.exe -s -o "$env:TEMP\r-hardened.pdf" -w "hardened: %{http_code} %{size_download} bytes`n" http://localhost:8000/devices/device-hardened/report.pdf
curl.exe -s -o "$env:TEMP\r-telnet.pdf"   -w "telnet:   %{http_code} %{size_download} bytes`n" http://localhost:8000/devices/telnet-sim/report.pdf
```

All three must return 200 with a non-trivial size. `device-insecure` is the dense case (8 evidence records, 3 verdicts); `telnet-sim` is the empty case (zero evidence) and must still produce a valid, sensible document.

- [ ] **Step 6: Open them and check the things tests cannot**

Copy them somewhere viewable and actually look:

- `§` and `—` render as characters, not blank boxes
- long `nmap`/`curl` commands wrap inside their column rather than overflowing the page
- the 64-character SHA-256 wraps and stays readable
- no finding block splits its clause from its verdict across a page break
- no heading is orphaned at the bottom of a page
- page numbers and the running header appear on every page
- `telnet-sim`'s report reads as "nothing was found" rather than looking broken
- the document reads as designed, not as a printed web page

- [ ] **Step 7: Get owner sign-off**

Send the three PDFs to the owner. **Do not mark this task complete without explicit sign-off** — passing tests told this project nothing about whether the Flutter dashboard looked right, and they tell you nothing here either.

- [ ] **Step 8: Commit any fixes and log any errors**

If verification found bugs, fix them, add `docs/errors/NNN-*.md` per `docs/errors/README.md`, and update its index.

---

## Verification Checklist

- [ ] API suite passes at 75 + new tests
- [ ] `npm test -- --run` and `npx tsc --noEmit` clean
- [ ] `GET /summary` on the PC unchanged at 13/8/4/4
- [ ] All 11 containers Up, none unhealthy
- [ ] Reports render for a device with evidence, a device with verdicts, and a device with neither
- [ ] `§`, `—` and SHA-256 strings visually confirmed in a real PDF
- [ ] No NCA emblem anywhere; the citation line is present
- [ ] Owner has signed off on the rendered documents
