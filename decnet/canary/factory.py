"""Generator and instrumenter factories.

Same lazy-import pattern as :mod:`decnet.intel.factory` — concrete
implementations stay un-imported until first use so importing
:mod:`decnet.canary` from a CLI subcommand doesn't drag in
``pikepdf`` / ``python-docx`` / ``Pillow`` for callers that only
need the model layer.
"""
from __future__ import annotations

from typing import Tuple

from decnet.canary.base import CanaryGenerator, CanaryInstrumenter

KNOWN_GENERATORS: Tuple[str, ...] = (
    "git_config",
    "env_file",
    "ssh_key",
    "aws_creds",
    "honeydoc",
    "honeydoc_docx",
    "honeydoc_pdf",
    "mysql_dump",
)

KNOWN_INSTRUMENTERS: Tuple[str, ...] = (
    "docx",
    "xlsx",
    "pdf",
    "html",
    "image",
    "plain",
    "passthrough",
)


def get_generator(name: str) -> CanaryGenerator:
    """Return the generator registered under ``name``.

    Raises :class:`ValueError` for unknown names so a typo in the API
    request surfaces as a 400 rather than silently producing nothing.
    """
    if name == "git_config":
        from decnet.canary.generators.git_config import GitConfigGenerator
        return GitConfigGenerator()
    if name == "env_file":
        from decnet.canary.generators.env_file import EnvFileGenerator
        return EnvFileGenerator()
    if name == "ssh_key":
        from decnet.canary.generators.ssh_key import SSHKeyGenerator
        return SSHKeyGenerator()
    if name == "aws_creds":
        from decnet.canary.generators.aws_creds import AWSCredsGenerator
        return AWSCredsGenerator()
    if name == "honeydoc":
        from decnet.canary.generators.honeydoc import HoneydocGenerator
        return HoneydocGenerator()
    if name == "honeydoc_docx":
        from decnet.canary.generators.honeydoc_docx import HoneydocDocxGenerator
        return HoneydocDocxGenerator()
    if name == "honeydoc_pdf":
        from decnet.canary.generators.honeydoc_pdf import HoneydocPdfGenerator
        return HoneydocPdfGenerator()
    if name == "mysql_dump":
        from decnet.canary.generators.mysql_dump import MySQLDumpGenerator
        return MySQLDumpGenerator()
    raise ValueError(
        f"Unknown canary generator: {name!r}. Known: {KNOWN_GENERATORS}"
    )


def get_instrumenter(name: str) -> CanaryInstrumenter:
    """Return the instrumenter registered under ``name``."""
    if name == "docx":
        from decnet.canary.instrumenters.docx import DocxInstrumenter
        return DocxInstrumenter()
    if name == "xlsx":
        from decnet.canary.instrumenters.xlsx import XlsxInstrumenter
        return XlsxInstrumenter()
    if name == "pdf":
        from decnet.canary.instrumenters.pdf import PdfInstrumenter
        return PdfInstrumenter()
    if name == "html":
        from decnet.canary.instrumenters.html import HtmlInstrumenter
        return HtmlInstrumenter()
    if name == "image":
        from decnet.canary.instrumenters.image import ImageInstrumenter
        return ImageInstrumenter()
    if name == "plain":
        from decnet.canary.instrumenters.plain import PlainInstrumenter
        return PlainInstrumenter()
    if name == "passthrough":
        from decnet.canary.instrumenters.passthrough import PassthroughInstrumenter
        return PassthroughInstrumenter()
    raise ValueError(
        f"Unknown canary instrumenter: {name!r}. Known: {KNOWN_INSTRUMENTERS}"
    )


# MIME → instrumenter dispatch.  Order matters: we walk the table
# top-to-bottom and the first prefix match wins, so put the more
# specific (DOCX/XLSX) before the generic (zip/octet-stream).
_MIME_DISPATCH: tuple[tuple[str, str], ...] = (
    # Office Open XML — DOCX/XLSX share a zip structure but expose
    # different inner trees, so dispatch by MIME alias rather than
    # zip-poking.
    ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
    ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
    ("application/pdf", "pdf"),
    ("text/html", "html"),
    ("application/xhtml+xml", "html"),
    ("image/png", "image"),
    ("image/jpeg", "image"),
    ("image/gif", "image"),
    # Plaintext catch-alls — config files, .env, .ini, .yaml, .json,
    # source code.  All handled by the same regex-substitution pass.
    ("text/", "plain"),
    ("application/json", "plain"),
    ("application/x-yaml", "plain"),
    ("application/yaml", "plain"),
    ("application/toml", "plain"),
)


def pick_instrumenter_for_mime(content_type: str) -> str:
    """Return the instrumenter name registered for a sniffed MIME.

    Falls back to ``"passthrough"`` for anything we don't have an
    embedder for (binary blobs we can't mutate safely — random
    container images, archives, executables).  ``passthrough`` only
    supports DNS-callback tokens (the slug ends up in the filename or
    an accompanying README), so the API surfaces that constraint to
    the operator before they pick a kind.
    """
    if not content_type:
        return "passthrough"
    lowered = content_type.lower()
    for prefix, name in _MIME_DISPATCH:
        if lowered.startswith(prefix):
            return name
    return "passthrough"
