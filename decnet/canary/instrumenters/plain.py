"""Plain-text / config-file instrumenter.

Two embedding strategies, picked in order:

1. **Token substitution.**  If the blob contains the literal
   placeholder ``{{CANARY_URL}}`` or ``{{CANARY_HOST}}``, replace it.
   This gives operators full control over where the slug lands —
   they can pre-edit the file with placeholders before uploading.
2. **Append.**  Otherwise, append a comment line that mentions the
   callback URL.  The comment style adapts to the file's apparent
   syntax (``#`` for shell/yaml/python/dockerfile, ``//`` for json5/
   javascript-ish, ``;`` for ini).

Operators who want neither behavior should upload the file as
``passthrough``.
"""
from __future__ import annotations

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryInstrumenter


_SLASH_HINTS = (b"//", b"function ", b"const ", b"let ", b"var ")
_SEMI_HINTS = (b"[default]", b"[section]", b"\n[")


def _comment_prefix(blob: bytes) -> bytes:
    head = blob[:512]
    if any(h in head for h in _SEMI_HINTS):
        return b"; "
    if any(h in head for h in _SLASH_HINTS):
        return b"// "
    # Default to # — the most common comment glyph across config files
    # we'd plausibly canary.
    return b"# "


class PlainInstrumenter(CanaryInstrumenter):
    name = "plain"
    mime_prefixes = ("text/", "application/json", "application/yaml", "application/toml")

    def instrument(
        self, blob: bytes, ctx: CanaryContext, *, target_path: str,
    ) -> CanaryArtifact:
        base = ctx.http_base.rstrip("/")
        callback_url = f"{base}/c/{ctx.callback_token}".encode()
        callback_host = (
            f"{ctx.callback_token}.{ctx.dns_zone}".encode()
            if ctx.dns_zone else b""
        )
        notes: list[str] = []
        out = blob

        if b"{{CANARY_URL}}" in blob:
            out = out.replace(b"{{CANARY_URL}}", callback_url)
            notes.append(f"substituted {{{{CANARY_URL}}}} -> {callback_url.decode()}")
        if b"{{CANARY_HOST}}" in blob and callback_host:
            out = out.replace(b"{{CANARY_HOST}}", callback_host)
            notes.append(f"substituted {{{{CANARY_HOST}}}} -> {callback_host.decode()}")

        if not notes:
            # No placeholders — append a comment line at the end.
            prefix = _comment_prefix(blob)
            tail = (
                b"\n" + prefix + b"see " + callback_url
                + b" for the latest version\n"
            )
            out = (out if out.endswith(b"\n") else out + b"\n") + tail
            notes.append(
                f"appended comment line carrying {callback_url.decode()}"
            )

        return CanaryArtifact(
            path=target_path,
            content=out,
            mode=0o644,
            mtime_offset=-86400 * 7,
            instrumenter=self.name,
            notes=notes,
        )
