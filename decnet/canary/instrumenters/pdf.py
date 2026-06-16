# SPDX-License-Identifier: AGPL-3.0-or-later
"""PDF instrumenter — requires :mod:`pikepdf` (optional dependency).

PDF embedding is non-trivial: the cleanest place to put a callback
is an ``/AA`` (additional actions) ``/O`` (open) entry on the
catalog or a ``/URI`` action on a link annotation.  Either path
needs proper xref-table updates — pikepdf handles that for us.

If pikepdf isn't available in the environment the instrumenter
raises :class:`InstrumenterRejectedError` so the API can return a
clear 400 directing the operator to either install pikepdf or
re-upload as ``passthrough``.

We don't ship a stdlib fallback because every "naive" PDF mutation
I'm aware of (appending raw bytes, splicing into the trailer, etc.)
breaks the document's xref table and trips a "file is corrupt"
warning in modern viewers — which the attacker will absolutely
notice.
"""
from __future__ import annotations

from decnet.canary.base import (
    CanaryArtifact,
    CanaryContext,
    CanaryInstrumenter,
    InstrumenterRejectedError,
)


class PdfInstrumenter(CanaryInstrumenter):
    name = "pdf"
    mime_prefixes = ("application/pdf",)

    def instrument(
        self, blob: bytes, ctx: CanaryContext, *, target_path: str,
    ) -> CanaryArtifact:
        try:
            import pikepdf
        except ImportError as e:
            raise InstrumenterRejectedError(
                "PDF instrumenter requires pikepdf; install it (`pip "
                "install pikepdf`) or re-upload the artifact with "
                "kind=passthrough so it ships unmodified."
            ) from e

        url = f"{ctx.http_base.rstrip('/')}/c/{ctx.callback_token}"
        try:
            import io
            buf = io.BytesIO(blob)
            with pikepdf.open(buf) as pdf:
                # Add an OpenAction that fires a URI action on document
                # open. Most viewers prompt before fetching; that's
                # fine — even the prompt itself can trip a "user
                # interacted with the document" tell, and an
                # auto-allow viewer fetches the URL silently.
                action = pikepdf.Dictionary(
                    Type=pikepdf.Name("/Action"),
                    S=pikepdf.Name("/URI"),
                    URI=pikepdf.String(url),
                )
                pdf.Root[pikepdf.Name("/OpenAction")] = action
                out = io.BytesIO()
                pdf.save(out)
                mutated = out.getvalue()
        except Exception as e:
            raise InstrumenterRejectedError(
                f"failed to instrument PDF: {e!s}"
            ) from e

        return CanaryArtifact(
            path=target_path,
            content=mutated,
            mode=0o644,
            mtime_offset=-86400 * 14,
            instrumenter=self.name,
            notes=[f"installed /OpenAction /URI -> {url}"],
        )
