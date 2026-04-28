"""DOCX instrumenter — inject a remote image into the body.

DOCX files are zip archives carrying ``word/document.xml`` (the body)
and ``word/_rels/document.xml.rels`` (the relationship table that
maps ``rId`` references to URLs).  We:

1. Add a new relationship of type ``image`` whose target is the
   canary callback URL and ``TargetMode="External"``.
2. Add a tiny ``<w:drawing>`` element referencing that ``rId`` at
   the end of ``word/document.xml`` (just before ``</w:body>``).

Word and LibreOffice both fetch external image relationships when
the document is opened (subject to the user's "trusted source"
toggle, which most enterprise environments disable in favour of
"warn but allow").

We use stdlib ``zipfile`` only — no python-docx dependency — because
the surface we touch is two small XML files and we don't need any of
the higher-level abstractions.
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Tuple

from decnet.canary.base import (
    CanaryArtifact,
    CanaryContext,
    CanaryInstrumenter,
    InstrumenterRejectedError,
)


_RELS_END = re.compile(rb"</Relationships\s*>", re.IGNORECASE)
_BODY_END = re.compile(rb"</w:body\s*>", re.IGNORECASE)


def _next_rid(rels_xml: bytes) -> str:
    """Return an rId not already taken in the relationships file.

    Word's loader tolerates non-sequential ids, so we just pick one
    well above the typical range to avoid collisions.
    """
    used = set(m.group(1).decode() for m in re.finditer(rb'Id="(rId\d+)"', rels_xml))
    for n in range(900, 9999):
        rid = f"rId{n}"
        if rid not in used:
            return rid
    raise InstrumenterRejectedError("DOCX has too many relationships to allocate a new rId")


def _inject_relationship(rels_xml: bytes, rid: str, url: str) -> bytes:
    rel = (
        f'<Relationship Id="{rid}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
        f'Target="{url}" TargetMode="External"/>'
    ).encode()
    match = _RELS_END.search(rels_xml)
    if not match:
        raise InstrumenterRejectedError(
            "DOCX rels file has no </Relationships>; refusing to mutate"
        )
    return rels_xml[:match.start()] + rel + rels_xml[match.start():]


def _drawing(rid: str) -> bytes:
    # Minimal w:drawing tree referencing the external image at rid.
    # Dimensions are 1 EMU x 1 EMU so the image is invisible; Word
    # still fetches the resource on document load.
    return (
        '<w:p><w:r><w:drawing>'
        '<wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
        '<wp:extent cx="1" cy="1"/><wp:docPr id="1" name="canary"/>'
        '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '<pic:nvPicPr><pic:cNvPr id="1" name="canary"/><pic:cNvPicPr/></pic:nvPicPr>'
        '<pic:blipFill>'
        f'<a:blip xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:link="{rid}"/>'
        '<a:stretch><a:fillRect/></a:stretch>'
        '</pic:blipFill>'
        '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="1" cy="1"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
        '</pic:pic></a:graphicData></a:graphic></wp:inline>'
        '</w:drawing></w:r></w:p>'
    ).encode()


def _inject_drawing(document_xml: bytes, rid: str) -> bytes:
    match = _BODY_END.search(document_xml)
    if not match:
        raise InstrumenterRejectedError("DOCX document.xml has no </w:body>")
    drawing = _drawing(rid)
    return document_xml[:match.start()] + drawing + document_xml[match.start():]


def _mutate(blob: bytes, url: str) -> Tuple[bytes, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
            try:
                rels = zf.read("word/_rels/document.xml.rels")
                doc = zf.read("word/document.xml")
            except KeyError as e:
                raise InstrumenterRejectedError(
                    f"DOCX missing expected member: {e.args[0]!r}"
                ) from e
            members = [(zi, zf.read(zi.filename)) for zi in zf.infolist()]
    except zipfile.BadZipFile as e:
        raise InstrumenterRejectedError("uploaded blob is not a valid DOCX zip") from e

    rid = _next_rid(rels)
    new_rels = _inject_relationship(rels, rid, url)
    new_doc = _inject_drawing(doc, rid)

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf_out:
        for zi, data in members:
            if zi.filename == "word/_rels/document.xml.rels":
                zf_out.writestr(zi.filename, new_rels)
            elif zi.filename == "word/document.xml":
                zf_out.writestr(zi.filename, new_doc)
            else:
                zf_out.writestr(zi, data)
    return out.getvalue(), rid


class DocxInstrumenter(CanaryInstrumenter):
    name = "docx"
    mime_prefixes = (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )

    def instrument(
        self, blob: bytes, ctx: CanaryContext, *, target_path: str,
    ) -> CanaryArtifact:
        url = f"{ctx.http_base.rstrip('/')}/c/{ctx.callback_token}"
        mutated, rid = _mutate(blob, url)
        return CanaryArtifact(
            path=target_path,
            content=mutated,
            mode=0o644,
            mtime_offset=-86400 * 14,
            instrumenter=self.name,
            notes=[f"injected external-image relationship {rid} -> {url}"],
        )
