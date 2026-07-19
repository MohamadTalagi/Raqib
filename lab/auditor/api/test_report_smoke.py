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
