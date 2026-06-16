# SPDX-License-Identifier: AGPL-3.0-or-later
"""Image instrumenter — requires :mod:`PIL` (optional dependency).

For PNG/JPEG/GIF we append a tEXt/EXIF chunk carrying the slug so
``exiftool`` / ``identify -verbose`` surface the slug, then route the
detection via a sibling **plain-text companion file**.  The image
itself can't really embed an HTTP fetcher — image decoders don't
run network requests on decode — so the realistic detection surface
is "attacker exfils the image, runs metadata tools on it, hits our
URL when curious about the embedded marker."

When Pillow isn't installed we reject and direct the operator to
``passthrough`` (which preserves the bytes; the slug then lives in
the filename only).
"""
from __future__ import annotations

import io

from decnet.canary.base import (
    CanaryArtifact,
    CanaryContext,
    CanaryInstrumenter,
    InstrumenterRejectedError,
)


class ImageInstrumenter(CanaryInstrumenter):
    name = "image"
    mime_prefixes = ("image/png", "image/jpeg", "image/gif")

    def instrument(
        self, blob: bytes, ctx: CanaryContext, *, target_path: str,
    ) -> CanaryArtifact:
        try:
            from PIL import Image, PngImagePlugin
        except ImportError as e:
            raise InstrumenterRejectedError(
                "image instrumenter requires Pillow; install it (`pip "
                "install Pillow`) or re-upload the artifact with "
                "kind=passthrough so it ships unmodified."
            ) from e

        slug_url = f"{ctx.http_base.rstrip('/')}/c/{ctx.callback_token}"
        try:
            buf_in = io.BytesIO(blob)
            img = Image.open(buf_in)
            fmt = (img.format or "").upper()
            buf_out = io.BytesIO()
            if fmt == "PNG":
                meta = PngImagePlugin.PngInfo()
                meta.add_text("Comment", f"reference: {slug_url}")
                meta.add_text("X-Canary", ctx.callback_token)
                img.save(buf_out, format="PNG", pnginfo=meta)
            elif fmt in ("JPEG", "JPG"):
                # Pillow encodes JPEG comments via the ``comment`` kwarg.
                img.save(buf_out, format="JPEG", comment=slug_url.encode())
            else:
                # GIF and friends — Pillow doesn't expose comment metadata
                # uniformly. Re-encode as-is and skip the metadata embed.
                img.save(buf_out, format=fmt or "PNG")
            mutated = buf_out.getvalue()
        except Exception as e:
            raise InstrumenterRejectedError(f"failed to instrument image: {e!s}") from e

        return CanaryArtifact(
            path=target_path,
            content=mutated,
            mode=0o644,
            mtime_offset=-86400 * 30,
            instrumenter=self.name,
            notes=[f"image metadata carries {slug_url} (slug={ctx.callback_token})"],
        )
