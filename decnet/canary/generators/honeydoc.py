"""Built-in honeydoc — a minimal HTML "report" with a tracking pixel.

This is the *fallback* honeydoc used when the operator hasn't
uploaded a real document.  The HTML instrumenter handles operator
uploads via :mod:`decnet.canary.instrumenters.html`; this generator
exists so the deploy-time baseline can plant *something* convincing
without first prompting the operator to drop a file.

The realism here is intentionally modest: a Documents-folder HTML
page with internal-looking content and a 1×1 remote image at the
bottom whose ``src`` is the canary callback URL.  Most desktop
HTML renderers fetch the image as soon as the file is opened in a
browser preview, so opening the doc trips the callback.

Operators who want a richer artifact should upload their own DOCX
or PDF; the corresponding instrumenter embeds the same callback in
the appropriate format.
"""
from __future__ import annotations

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryGenerator


class HoneydocGenerator(CanaryGenerator):
    name = "honeydoc"

    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        base = ctx.http_base.rstrip("/")
        slug = ctx.callback_token
        pixel_url = f"{base}/c/{slug}"
        body = (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<title>Q3 Operations Review — DRAFT</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1>Q3 Operations Review (DRAFT — DO NOT DISTRIBUTE)</h1>\n"
            "<p>Forecast and remediation timeline below. Numbers are\n"
            "preliminary and subject to revision before the all-hands.</p>\n"
            "<table>\n"
            "<tr><th>Region</th><th>Incidents</th><th>MTTR (h)</th></tr>\n"
            "<tr><td>us-east</td><td>14</td><td>3.2</td></tr>\n"
            "<tr><td>us-west</td><td>9</td><td>4.7</td></tr>\n"
            "<tr><td>eu-central</td><td>22</td><td>2.1</td></tr>\n"
            "</table>\n"
            "<p>Internal contact: <a href=\"mailto:secops@internal\">"
            "secops@internal</a></p>\n"
            f"<img src=\"{pixel_url}\" width=\"1\" height=\"1\" alt=\"\">\n"
            "</body>\n"
            "</html>\n"
        )
        return CanaryArtifact(
            path="",
            content=body.encode("utf-8"),
            mode=0o644,  # docs are typically world-readable
            mtime_offset=-86400 * 21,  # 3 weeks ago
            generator=self.name,
            notes=[f"tracking pixel src={pixel_url}"],
        )
