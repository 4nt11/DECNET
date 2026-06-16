# SPDX-License-Identifier: AGPL-3.0-or-later
"""Coverage for the operator-upload instrumenters.

Each instrumenter is round-tripped against a small, real-shaped
fixture.  We assert:

* the callback URL ends up somewhere in the mutated bytes;
* the output still parses (zip stays a valid zip; HTML stays
  reasonable);
* the rejection paths surface :class:`InstrumenterRejectedError`
  with a useful message.
"""
from __future__ import annotations

import io
import zipfile

import pytest

from decnet.canary import CanaryContext, get_instrumenter
from decnet.canary.base import InstrumenterRejectedError


def _ctx(slug: str = "slug-abc") -> CanaryContext:
    return CanaryContext(
        callback_token=slug,
        http_base="https://canary.example.test",
        dns_zone="canary.example.test",
        persona="linux",
    )


# ----------------------- passthrough ------------------------------------

def test_passthrough_preserves_bytes() -> None:
    ins = get_instrumenter("passthrough")
    out = ins.instrument(b"\x00\x01\x02bin", _ctx(), target_path="/tmp/x.bin")
    assert out.content == b"\x00\x01\x02bin"
    assert out.path == "/tmp/x.bin"
    assert out.instrumenter == "passthrough"


# ----------------------- plain ------------------------------------------

def test_plain_substitutes_url_placeholder() -> None:
    ins = get_instrumenter("plain")
    blob = b"api: {{CANARY_URL}}\nhost: {{CANARY_HOST}}\n"
    out = ins.instrument(blob, _ctx("slugXYZ"), target_path="/etc/x.yaml")
    assert b"https://canary.example.test/c/slugXYZ" in out.content
    assert b"slugXYZ.canary.example.test" in out.content
    assert b"{{CANARY_URL}}" not in out.content


def test_plain_appends_when_no_placeholder() -> None:
    ins = get_instrumenter("plain")
    out = ins.instrument(b"key=value\n", _ctx("s1"), target_path="/etc/x.env")
    assert b"https://canary.example.test/c/s1" in out.content
    # Original content survives.
    assert out.content.startswith(b"key=value\n")


@pytest.mark.parametrize(
    "head, expect_prefix",
    [
        (b"[default]\nfoo=1\n", b"; "),
        (b"// js code\nconst x = 1;\n", b"// "),
        (b"#!/bin/bash\necho hi\n", b"# "),
    ],
)
def test_plain_picks_comment_prefix(head: bytes, expect_prefix: bytes) -> None:
    ins = get_instrumenter("plain")
    out = ins.instrument(head, _ctx(), target_path="/etc/x")
    # The appended comment line uses the matching prefix.
    appended = out.content[len(head):]
    assert appended.lstrip(b"\n").startswith(expect_prefix)


# ----------------------- html -------------------------------------------

def test_html_injects_pixel_before_body_close() -> None:
    ins = get_instrumenter("html")
    blob = b"<html><body><h1>hi</h1></body></html>"
    out = ins.instrument(blob, _ctx("slugH"), target_path="/srv/x.html")
    assert b"https://canary.example.test/c/slugH" in out.content
    # Pixel sits before </body>, not after.
    body_close = out.content.index(b"</body>")
    pixel_pos = out.content.index(b"<img ")
    assert pixel_pos < body_close
    # Original markup survives intact.
    assert b"<h1>hi</h1>" in out.content


def test_html_appends_pixel_when_body_missing() -> None:
    ins = get_instrumenter("html")
    out = ins.instrument(b"<p>no body</p>", _ctx(), target_path="/srv/x.html")
    assert out.content.endswith(b">\n") or out.content.endswith(b'>\n')
    assert b"<img" in out.content


# ----------------------- docx -------------------------------------------

def test_docx_injects_external_image_relationship(minimal_docx: bytes) -> None:
    ins = get_instrumenter("docx")
    out = ins.instrument(minimal_docx, _ctx("slugD"), target_path="/x/r.docx")
    # Output is still a valid zip we can re-open.
    with zipfile.ZipFile(io.BytesIO(out.content), "r") as zf:
        rels = zf.read("word/_rels/document.xml.rels").decode()
        doc = zf.read("word/document.xml").decode()
    assert "https://canary.example.test/c/slugD" in rels
    assert "TargetMode=\"External\"" in rels
    assert "image" in rels
    # Drawing is embedded in the document body, before </w:body>.
    assert "<w:drawing>" in doc
    assert doc.index("<w:drawing>") < doc.index("</w:body>")


def test_docx_rejects_non_zip() -> None:
    ins = get_instrumenter("docx")
    with pytest.raises(InstrumenterRejectedError, match="not a valid DOCX"):
        ins.instrument(b"not a docx at all", _ctx(), target_path="/x")


def test_docx_rejects_zip_missing_members() -> None:
    ins = get_instrumenter("docx")
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("readme.txt", "hello")
    with pytest.raises(InstrumenterRejectedError, match="missing expected member"):
        ins.instrument(out.getvalue(), _ctx(), target_path="/x")


# ----------------------- xlsx -------------------------------------------

def test_xlsx_injects_relationship(minimal_xlsx: bytes) -> None:
    ins = get_instrumenter("xlsx")
    out = ins.instrument(minimal_xlsx, _ctx("slugX"), target_path="/x/r.xlsx")
    with zipfile.ZipFile(io.BytesIO(out.content), "r") as zf:
        rels = zf.read("xl/_rels/workbook.xml.rels").decode()
    assert "https://canary.example.test/c/slugX" in rels
    assert "TargetMode=\"External\"" in rels


def test_xlsx_rejects_zip_without_workbook_rels() -> None:
    ins = get_instrumenter("xlsx")
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("readme.txt", "hello")
    with pytest.raises(InstrumenterRejectedError, match="no workbook relationships"):
        ins.instrument(out.getvalue(), _ctx(), target_path="/x")


# ----------------------- pdf / image (optional dep) ---------------------

def test_pdf_rejects_when_pikepdf_missing() -> None:
    pytest.importorskip  # noqa: B018 — fence below
    try:
        import pikepdf  # noqa: F401
    except ImportError:
        ins = get_instrumenter("pdf")
        with pytest.raises(InstrumenterRejectedError, match="pikepdf"):
            ins.instrument(b"%PDF-1.4\n", _ctx(), target_path="/x.pdf")
    else:
        pytest.skip("pikepdf is installed; skipping the missing-dep guard")


def test_image_rejects_when_pillow_missing() -> None:
    try:
        import PIL  # noqa: F401
    except ImportError:
        ins = get_instrumenter("image")
        with pytest.raises(InstrumenterRejectedError, match="Pillow"):
            ins.instrument(b"\x89PNG\r\n", _ctx(), target_path="/x.png")
    else:
        pytest.skip("Pillow is installed; skipping the missing-dep guard")
