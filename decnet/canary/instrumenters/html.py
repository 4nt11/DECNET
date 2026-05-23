# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTML instrumenter — append a 1×1 tracking pixel.

Stdlib-only.  We don't parse the HTML; we just inject the ``<img>``
tag immediately before the closing ``</body>`` (or, failing that, at
the end of the document).  Most renderers that support remote images
(email previewers, IDE doc previews, browsers) will fetch it as
soon as the document is opened.
"""
from __future__ import annotations

import re

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryInstrumenter


_BODY_CLOSE = re.compile(rb"</body\s*>", re.IGNORECASE)


class HtmlInstrumenter(CanaryInstrumenter):
    name = "html"
    mime_prefixes = ("text/html", "application/xhtml+xml")

    def instrument(
        self, blob: bytes, ctx: CanaryContext, *, target_path: str,
    ) -> CanaryArtifact:
        url = f"{ctx.http_base.rstrip('/')}/c/{ctx.callback_token}".encode()
        pixel = (
            b"<img src=\"" + url + b"\" width=\"1\" height=\"1\" "
            b"alt=\"\" style=\"display:none\">\n"
        )
        match = _BODY_CLOSE.search(blob)
        if match:
            out = blob[:match.start()] + pixel + blob[match.start():]
            note = "injected 1x1 pixel before </body>"
        else:
            out = (blob if blob.endswith(b"\n") else blob + b"\n") + pixel
            note = "appended 1x1 pixel (no </body> found)"
        return CanaryArtifact(
            path=target_path,
            content=out,
            mode=0o644,
            mtime_offset=-86400 * 7,
            instrumenter=self.name,
            notes=[note, f"pixel src={url.decode()}"],
        )
