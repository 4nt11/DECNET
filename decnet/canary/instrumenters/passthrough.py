# SPDX-License-Identifier: AGPL-3.0-or-later
"""Passthrough instrumenter — bytes go to disk unchanged.

Used as the dispatch fallback for content types we can't safely
mutate (random binary blobs, container images, archives we don't
recognise).  In passthrough mode the only callback surface is the
:attr:`CanaryToken.placement_path` itself: the operator must use a
DNS-callback token whose slug appears in the filename, so a
listing/access at the OS level resolves the slug as part of the
path (e.g. ``/etc/<slug>.canary.example.test/secrets.bin``) when
the attacker greps for hostnames in their loot.

The instrumenter does not enforce that — the API does, when it sees
``instrumenter=passthrough`` with ``kind=http`` it returns 400.
"""
from __future__ import annotations

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryInstrumenter


class PassthroughInstrumenter(CanaryInstrumenter):
    name = "passthrough"
    mime_prefixes = ()  # dispatched by fallback in pick_instrumenter_for_mime

    def instrument(
        self, blob: bytes, ctx: CanaryContext, *, target_path: str,
    ) -> CanaryArtifact:
        return CanaryArtifact(
            path=target_path,
            content=blob,
            mode=0o644,
            mtime_offset=-86400 * 7,
            instrumenter=self.name,
            notes=[
                "passthrough: bytes unchanged — only DNS-callback tokens "
                "trip detection (slug must live in the placement path)",
            ],
        )
