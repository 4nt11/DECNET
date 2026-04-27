"""Coverage for the generator/instrumenter factory + MIME dispatch.

The concrete generators and instrumenters land in subsequent commits;
this file only tests the dispatch surface — it must reject unknown
names with ``ValueError`` and pick the right instrumenter for known
MIME types (with passthrough as the fallback for binary blobs we
can't safely mutate).
"""
from __future__ import annotations

import pytest

from decnet.canary.factory import (
    KNOWN_GENERATORS,
    KNOWN_INSTRUMENTERS,
    pick_instrumenter_for_mime,
)


@pytest.mark.parametrize(
    "mime, expected",
    [
        ("application/pdf", "pdf"),
        ("application/PDF", "pdf"),  # case-insensitive
        ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
        ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
        ("text/html", "html"),
        ("application/xhtml+xml", "html"),
        ("text/plain", "plain"),
        ("text/x-yaml", "plain"),
        ("application/json", "plain"),
        ("application/yaml", "plain"),
        ("application/toml", "plain"),
        ("image/png", "image"),
        ("image/jpeg", "image"),
        ("image/gif", "image"),
    ],
)
def test_mime_dispatch_known(mime: str, expected: str) -> None:
    assert pick_instrumenter_for_mime(mime) == expected


@pytest.mark.parametrize(
    "mime",
    [
        "",
        "application/octet-stream",
        "application/x-tar",
        "application/zip",  # bare zip — DOCX/XLSX dispatch by alias, not raw zip
        "video/mp4",
        "audio/mpeg",
    ],
)
def test_mime_dispatch_falls_back_to_passthrough(mime: str) -> None:
    assert pick_instrumenter_for_mime(mime) == "passthrough"


def test_known_lists_are_stable() -> None:
    # If anyone adds/removes from the dispatch tables, the test
    # surfaces it. Keeps the schema-of-record in one place.
    assert KNOWN_GENERATORS == (
        "git_config", "env_file", "ssh_key", "aws_creds",
        "honeydoc", "honeydoc_docx", "honeydoc_pdf",
    )
    assert KNOWN_INSTRUMENTERS == (
        "docx", "xlsx", "pdf", "html", "image", "plain", "passthrough",
    )


def test_unknown_generator_raises() -> None:
    from decnet.canary.factory import get_generator
    with pytest.raises(ValueError, match="Unknown canary generator"):
        get_generator("bogus")


def test_unknown_instrumenter_raises() -> None:
    from decnet.canary.factory import get_instrumenter
    with pytest.raises(ValueError, match="Unknown canary instrumenter"):
        get_instrumenter("bogus")


def test_base_artifact_dataclass_defaults() -> None:
    from decnet.canary import CanaryArtifact
    a = CanaryArtifact(path="/x", content=b"y")
    assert a.mode == 0o600
    assert a.mtime_offset == 0
    assert a.notes == []
    assert a.generator is None and a.instrumenter is None
