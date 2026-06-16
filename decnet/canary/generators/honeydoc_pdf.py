# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real-PDF honeydoc generator (uses :mod:`pikepdf`).

Builds a one-page PDF with the same Q3-review body as the HTML/DOCX
flavors and installs an ``/OpenAction`` ``/URI`` action on the
catalog so most viewers fire the callback the moment the document
opens.

Pikepdf is now a hard dependency for this generator (the operator
installed it explicitly so we can use it).  We still surface a
clear :class:`InstrumenterRejectedError` when imports fail, so a
deployment without pikepdf can fall back to the DOCX or HTML
generators rather than crashing the API.
"""
from __future__ import annotations

import io

from decnet.canary.base import (
    CanaryArtifact,
    CanaryContext,
    CanaryGenerator,
    InstrumenterRejectedError,
)


_BODY_LINES = (
    ("Q3 Operations Review (DRAFT — DO NOT DISTRIBUTE)", 14),
    ("", 12),
    ("Forecast and remediation timeline below.", 11),
    ("Numbers are preliminary, subject to revision.", 11),
    ("", 12),
    ("Region        Incidents     MTTR (h)", 11),
    ("us-east       14            3.2", 11),
    ("us-west       9             4.7",  11),
    ("eu-central    22            2.1",  11),
    ("", 12),
    ("Internal contact: secops@internal", 11),
)


class HoneydocPdfGenerator(CanaryGenerator):
    name = "honeydoc_pdf"

    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        try:
            from pikepdf import Pdf, Name, Dictionary, String
        except ImportError as e:
            raise InstrumenterRejectedError(
                "honeydoc_pdf requires pikepdf; install it (`pip install "
                "pikepdf`) or pick honeydoc / honeydoc_docx instead."
            ) from e

        url = f"{ctx.http_base.rstrip('/')}/c/{ctx.callback_token}"

        pdf = Pdf.new()
        # Helvetica is one of the 14 PDF base fonts — every viewer ships
        # it, so no font embedding is required.
        font = pdf.make_indirect(Dictionary(
            Type=Name("/Font"),
            Subtype=Name("/Type1"),
            BaseFont=Name("/Helvetica"),
        ))

        # Build a single content stream that writes each body line at a
        # decreasing y-coordinate.  PDF coordinates start at the bottom-
        # left (US Letter = 612 x 792 points); we lay out lines roughly
        # 18 points apart starting near the top.
        ops: list[str] = ["BT /F1 12 Tf 72 750 Td"]
        first = True
        for line, size in _BODY_LINES:
            if not first:
                ops.append("0 -18 Td")
            first = False
            ops.append(f"/F1 {size} Tf")
            ops.append(f"({_pdf_escape(line)}) Tj")
        ops.append("ET")
        content_bytes = "\n".join(ops).encode("latin-1")

        content_stream = pdf.make_stream(content_bytes)

        page = pdf.add_blank_page(page_size=(612, 792))
        page[Name("/Resources")] = Dictionary(
            Font=Dictionary(F1=font),
        )
        page[Name("/Contents")] = content_stream

        # OpenAction fires the URI when the file is opened in Acrobat,
        # Preview, the browser PDF viewer, etc.  Most viewers prompt
        # before fetching; that prompt itself is a tell, and an
        # auto-allow viewer fetches silently.
        pdf.Root[Name("/OpenAction")] = Dictionary(
            Type=Name("/Action"),
            S=Name("/URI"),
            URI=String(url),
        )

        out = io.BytesIO()
        pdf.save(out)
        return CanaryArtifact(
            path="",
            content=out.getvalue(),
            mode=0o644,
            mtime_offset=-86400 * 21,
            generator=self.name,
            notes=[
                "synthesised one-page PDF with realistic Q3 review body",
                f"/OpenAction /URI -> {url}",
            ],
        )


def _pdf_escape(s: str) -> str:
    """Escape parens and backslashes for PDF literal-string syntax.

    PDF string literals are wrapped in ``( … )``; inner ``(``, ``)``,
    and ``\\`` need backslash escapes.  Everything else (including
    UTF-8 multibyte sequences) round-trips fine because Helvetica's
    encoding is WinAnsi-ish — we'll lose exotic glyphs but the
    realistic body sticks to ASCII anyway.  Em-dashes are downgraded
    to ``--`` to avoid the WinAnsi gap.
    """
    return (
        s.replace("\\", r"\\")
         .replace("(", r"\(")
         .replace(")", r"\)")
         .replace("—", "--")
    )
