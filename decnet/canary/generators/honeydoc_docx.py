# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real-DOCX honeydoc generator.

Synthesises a minimal but structurally valid DOCX from scratch via
stdlib :mod:`zipfile`, then uses the same external-image relationship
trick that powers :mod:`decnet.canary.instrumenters.docx` to embed
the callback URL.  No python-docx dependency.

The output opens cleanly in Word / LibreOffice; both fetch the
external image relationship on document load.
"""
from __future__ import annotations

import io
import zipfile

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryGenerator
from decnet.canary.instrumenters.docx import _drawing, _next_rid


_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '</Types>'
).encode()

_PACKAGE_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/>'
    '</Relationships>'
).encode()

_BODY_PARAGRAPHS = (
    "Q3 Operations Review (DRAFT — DO NOT DISTRIBUTE)",
    "",
    "Forecast and remediation timeline below. Numbers are preliminary "
    "and subject to revision before the all-hands.",
    "",
    "Region        Incidents     MTTR (h)",
    "us-east       14            3.2",
    "us-west       9             4.7",
    "eu-central    22            2.1",
    "",
    "Internal contact: secops@internal",
)


def _document_xml(rid_with_drawing: str | None = None) -> bytes:
    """Build the body XML.

    ``rid_with_drawing`` is the rId of the external image relationship;
    when set, we append the same ``<w:drawing>`` element that the DOCX
    instrumenter inserts so the body references the external resource.
    """
    paragraphs = []
    for line in _BODY_PARAGRAPHS:
        if line:
            paragraphs.append(
                "<w:p><w:r><w:t xml:space=\"preserve\">"
                + _xml_escape(line)
                + "</w:t></w:r></w:p>"
            )
        else:
            paragraphs.append("<w:p/>")
    body = "".join(paragraphs)
    drawing = _drawing(rid_with_drawing).decode() if rid_with_drawing else ""
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:body>{body}{drawing}</w:body>'
        '</w:document>'
    ).encode()


def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
    )


def _document_rels(rid: str, url: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="{rid}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
        f'Target="{url}" TargetMode="External"/>'
        '</Relationships>'
    ).encode()


class HoneydocDocxGenerator(CanaryGenerator):
    name = "honeydoc_docx"

    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        url = f"{ctx.http_base.rstrip('/')}/c/{ctx.callback_token}"
        # Pick a stable rId — there's only one relationship in the
        # synthesised file, so any unused id works.  Reuse the
        # instrumenter's allocator against the bare relationships
        # skeleton for parity with operator-uploaded DOCX flow.
        skeleton = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'</Relationships>'
        )
        rid = _next_rid(skeleton)

        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
            zf.writestr("_rels/.rels", _PACKAGE_RELS)
            zf.writestr("word/document.xml", _document_xml(rid))
            zf.writestr("word/_rels/document.xml.rels", _document_rels(rid, url))

        return CanaryArtifact(
            path="",
            content=out.getvalue(),
            mode=0o644,
            mtime_offset=-86400 * 21,
            generator=self.name,
            notes=[
                "synthesised DOCX with realistic Q3 review body",
                f"external-image relationship {rid} -> {url}",
            ],
        )
