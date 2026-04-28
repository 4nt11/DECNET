"""XLSX instrumenter — embed an external-image link.

XLSX is structurally identical to DOCX (Office Open XML zip).  The
injection target is the workbook's relationships file
(``xl/_rels/workbook.xml.rels``).  We add an external image
relationship there; Excel/LibreOffice fetch external images on
workbook open in the same way Word does.

We don't inject a ``<drawing>`` element into a sheet because that
requires touching ``xl/worksheets/sheetN.xml`` *and* allocating a new
``xl/drawings/drawingN.xml`` part — much higher chance of mangling
the file.  An orphan external image relationship is enough: many
Office viewers fetch all relationships at open time regardless of
whether they're referenced from a sheet.

If the operator wants a stronger trigger (image visible in the
sheet, fetched even by viewers that lazy-load external resources)
they should embed the slug as a hyperlink cell content via the
``plain``/``passthrough`` instrumenters.
"""
from __future__ import annotations

import io
import zipfile
from typing import Tuple

from decnet.canary.base import (
    CanaryArtifact,
    CanaryContext,
    CanaryInstrumenter,
    InstrumenterRejectedError,
)
from decnet.canary.instrumenters.docx import _inject_relationship, _next_rid


_RELS_PATHS = (
    "xl/_rels/workbook.xml.rels",
    "xl/_rels/sharedStrings.xml.rels",
)


def _mutate(blob: bytes, url: str) -> Tuple[bytes, str, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
            members = [(zi, zf.read(zi.filename)) for zi in zf.infolist()]
    except zipfile.BadZipFile as e:
        raise InstrumenterRejectedError("uploaded blob is not a valid XLSX zip") from e

    target_rels: str | None = None
    for zi, _ in members:
        if zi.filename in _RELS_PATHS:
            target_rels = zi.filename
            break
    if not target_rels:
        raise InstrumenterRejectedError(
            "XLSX has no workbook relationships file to mutate"
        )

    out_members = []
    rid = ""
    for zi, data in members:
        if zi.filename == target_rels:
            rid = _next_rid(data)
            data = _inject_relationship(data, rid, url)
        out_members.append((zi, data))

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf_out:
        for zi, data in out_members:
            zf_out.writestr(zi, data)
    return out.getvalue(), rid, target_rels


class XlsxInstrumenter(CanaryInstrumenter):
    name = "xlsx"
    mime_prefixes = (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

    def instrument(
        self, blob: bytes, ctx: CanaryContext, *, target_path: str,
    ) -> CanaryArtifact:
        url = f"{ctx.http_base.rstrip('/')}/c/{ctx.callback_token}"
        mutated, rid, target_rels = _mutate(blob, url)
        return CanaryArtifact(
            path=target_path,
            content=mutated,
            mode=0o644,
            mtime_offset=-86400 * 14,
            instrumenter=self.name,
            notes=[
                f"injected external-image relationship {rid} into "
                f"{target_rels} -> {url}",
            ],
        )
