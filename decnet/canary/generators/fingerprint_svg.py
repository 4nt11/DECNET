"""SVG fingerprint canary — standalone SVG with an embedded ``<script>``
that runs the obfuscated fingerprinter when the file is opened directly
in a browser.

SVG ``<script>`` only fires when the SVG is loaded as a top-level
document (or via ``<object>``/``<iframe>``); it's *blocked* when the
SVG is referenced from another page's ``<img>``.  That's the right
posture for canary use: an attacker browsing the decky filesystem and
double-clicking a stray ``network_diagram.svg`` triggers it; rendering
inside a sandboxed CMS preview does not.

Same determinism guarantees as :mod:`fingerprint_html`.
"""
from __future__ import annotations

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryGenerator
from decnet.canary.generators.fingerprint_html import _mint_uuid_for, _stable_int
from decnet.canary.obfuscator import render_fingerprint_js, nonce_for


_DIAGRAM_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 360" width="600" height="360">
<style>
.box{{fill:#f7f9fb;stroke:#7a93ad;stroke-width:1.2}}
.lbl{{font:12px Segoe UI,Arial,sans-serif;fill:#2a3a4a}}
.edge{{stroke:#7a93ad;stroke-width:1.2;fill:none}}
.title{{font:bold 14px Segoe UI,Arial,sans-serif;fill:#1a2a3a}}
.cap{{font:10px Segoe UI,Arial,sans-serif;fill:#6a7a8a}}
</style>
<text class="title" x="20" y="28">Network Topology — {region} segment</text>
<text class="cap" x="20" y="44">draft v{ver} · last reviewed {review}</text>
<rect class="box" x="40" y="80" width="120" height="50" rx="4"/>
<text class="lbl" x="100" y="110" text-anchor="middle">edge gw</text>
<rect class="box" x="240" y="80" width="120" height="50" rx="4"/>
<text class="lbl" x="300" y="110" text-anchor="middle">core sw</text>
<rect class="box" x="440" y="80" width="120" height="50" rx="4"/>
<text class="lbl" x="500" y="110" text-anchor="middle">app cluster</text>
<rect class="box" x="240" y="220" width="120" height="50" rx="4"/>
<text class="lbl" x="300" y="250" text-anchor="middle">db tier</text>
<path class="edge" d="M160 105 L240 105"/>
<path class="edge" d="M360 105 L440 105"/>
<path class="edge" d="M300 130 L300 220"/>
<script type="application/ecmascript"><![CDATA[
{payload}
]]></script>
</svg>
"""


_REGIONS = ("us-east", "eu-central", "ap-south", "us-west", "sa-east")


class FingerprintSvgGenerator(CanaryGenerator):
    """Synthesise an SVG that fingerprints the browser opening it."""

    name = "fingerprint_svg"

    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        mint_uuid = _mint_uuid_for(ctx.callback_token)
        nonce = nonce_for(ctx.callback_token, mint_uuid)
        payload = render_fingerprint_js(
            callback_token=ctx.callback_token,
            http_base=ctx.http_base,
            mint_uuid=mint_uuid,
            nonce=nonce,
        )
        region = _REGIONS[_stable_int(ctx.callback_token, "reg") % len(_REGIONS)]
        ver = 1 + (_stable_int(ctx.callback_token, "ver") % 6)
        day = _stable_int(ctx.callback_token, "day") % 28 + 1
        body = _DIAGRAM_TEMPLATE.format(
            region=region,
            ver=ver,
            review=f"2026-03-{day:02d}",
            payload=payload,
        )
        beacon = f"{ctx.http_base.rstrip('/')}/c/{ctx.callback_token}"
        return CanaryArtifact(
            path="",
            content=body.encode("utf-8"),
            mode=0o644,
            mtime_offset=-86400 * 30,
            generator=self.name,
            fingerprint_nonce=nonce,
            notes=[
                f"obfuscated fingerprinter beacons={beacon}",
                f"mint_uuid={mint_uuid}",
            ],
        )
