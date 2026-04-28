"""Coverage for the synthesised-artifact generators.

Each generator MUST be deterministic for a given ``CanaryContext`` —
the planter relies on that idempotency to re-seed without storing
the rendered bytes.  We assert byte-for-byte stability across two
calls with the same inputs as well as the obvious "slug appears in
the artifact" property.
"""
from __future__ import annotations

import re

import pytest

from decnet.canary import CanaryContext, get_generator
from decnet.canary.factory import KNOWN_GENERATORS


def _ctx(**kw) -> CanaryContext:
    defaults = dict(
        callback_token="abcDEF123-test",
        http_base="https://canary.example.test",
        dns_zone="canary.example.test",
        persona="linux",
    )
    defaults.update(kw)
    return CanaryContext(**defaults)


@pytest.mark.parametrize("name", KNOWN_GENERATORS)
def test_generator_is_deterministic(name: str) -> None:
    g = get_generator(name)
    a = g.generate(_ctx())
    b = g.generate(_ctx())
    assert a.content == b.content, f"{name} not deterministic"
    assert a.generator == name
    assert a.instrumenter is None
    assert a.mode in (0o600, 0o644)


@pytest.mark.parametrize("name", ["git_config", "env_file", "honeydoc"])
def test_callback_url_embedded(name: str) -> None:
    g = get_generator(name)
    art = g.generate(_ctx(callback_token="slug-XYZ"))
    body = art.content.decode("utf-8")
    assert "slug-XYZ" in body, f"{name} did not embed slug"
    assert "https://canary.example.test" in body


def test_aws_creds_passive_does_not_embed_url() -> None:
    # AWS creds are passive — there's no realistic field to hide a URL
    # in. Asserting the absence prevents a regression where a future
    # change tries to slip the slug into a comment and breaks realism.
    g = get_generator("aws_creds")
    art = g.generate(_ctx(callback_token="slug-XYZ"))
    body = art.content.decode("utf-8")
    assert "https://" not in body
    assert "slug-XYZ" not in body
    # Access key matches the AKIA[A-Z0-9]{16} shape.
    assert re.search(r"AKIA[A-Z0-9]{16}", body)


def test_aws_creds_changes_with_slug() -> None:
    g = get_generator("aws_creds")
    a = g.generate(_ctx(callback_token="slug-A"))
    b = g.generate(_ctx(callback_token="slug-B"))
    assert a.content != b.content


def test_ssh_key_uses_dns_zone_when_available() -> None:
    g = get_generator("ssh_key")
    art = g.generate(_ctx(callback_token="slugZ", dns_zone="canary.test"))
    assert b"slugZ.canary.test" in art.content


def test_ssh_key_falls_back_to_http_host_without_dns() -> None:
    g = get_generator("ssh_key")
    art = g.generate(_ctx(
        http_base="https://example.test", dns_zone="",
    ))
    assert b"example.test" in art.content


def test_honeydoc_html_is_valid_ish_html() -> None:
    g = get_generator("honeydoc")
    art = g.generate(_ctx())
    body = art.content.decode("utf-8")
    assert "<!DOCTYPE html>" in body
    assert "<img" in body
    assert "width=\"1\" height=\"1\"" in body


def test_honeydoc_docx_produces_valid_zip_with_callback() -> None:
    import io
    import zipfile
    g = get_generator("honeydoc_docx")
    art = g.generate(_ctx(callback_token="slugDX"))
    assert art.content[:4] == b"PK\x03\x04"  # zip magic
    with zipfile.ZipFile(io.BytesIO(art.content), "r") as zf:
        names = set(zf.namelist())
        assert {"[Content_Types].xml", "_rels/.rels", "word/document.xml",
                "word/_rels/document.xml.rels"} <= names
        rels = zf.read("word/_rels/document.xml.rels").decode()
        assert "https://canary.example.test/c/slugDX" in rels
        assert "TargetMode=\"External\"" in rels
        doc = zf.read("word/document.xml").decode()
        assert "Q3 Operations Review" in doc
        assert "<w:drawing>" in doc


def test_honeydoc_pdf_produces_valid_pdf_with_openaction() -> None:
    pikepdf = pytest.importorskip("pikepdf")
    g = get_generator("honeydoc_pdf")
    art = g.generate(_ctx(callback_token="slugPDF"))
    assert art.content[:5] == b"%PDF-"
    # Re-open and confirm OpenAction URI round-trips.
    import io
    with pikepdf.open(io.BytesIO(art.content)) as pdf:
        action = pdf.Root["/OpenAction"]
        assert str(action["/S"]) == "/URI"
        assert str(action["/URI"]) == "https://canary.example.test/c/slugPDF"


def test_git_config_remote_url_shape() -> None:
    g = get_generator("git_config")
    art = g.generate(_ctx(callback_token="slug42"))
    body = art.content.decode("utf-8")
    assert "[remote \"origin\"]" in body
    assert "https://canary.example.test/c/slug42/repo.git" in body


def test_env_file_carries_two_callback_fields() -> None:
    g = get_generator("env_file")
    art = g.generate(_ctx(callback_token="slugEnv"))
    body = art.content.decode("utf-8")
    assert "API_BASE_URL=https://canary.example.test/c/slugEnv" in body
    assert "WEBHOOK_NOTIFY_URL=https://canary.example.test/c/slugEnv/webhook" in body


def test_mysql_dump_requires_dns_zone() -> None:
    g = get_generator("mysql_dump")
    with pytest.raises(ValueError, match="dns_zone"):
        g.generate(_ctx(dns_zone=""))


def test_mysql_dump_payload_round_trips_through_base64() -> None:
    import base64 as _b64
    g = get_generator("mysql_dump")
    art = g.generate(_ctx(callback_token="slugSQL", dns_zone="canary.test"))
    body = art.content.decode("utf-8")
    # Slug must NOT appear in plaintext — the camouflage is base64.
    assert "slugSQL" not in body.replace("\n", " ").split("SET @b = '")[0]
    # Locate the base64 blob and decode it; the inner SQL must reference
    # the slug-bearing replica host, smuggle @@hostname/@@lc_time_names
    # into SOURCE_USER, and target port 3306.
    m = re.search(r"SET @b = '([A-Za-z0-9+/=]+)';", body)
    assert m, "expected base64 payload assignment"
    inner = _b64.b64decode(m.group(1)).decode("utf-8")
    assert "slugSQL.canary.test" in inner
    assert "SOURCE_PORT=3306" in inner
    assert "@@hostname" in inner
    assert "@@lc_time_names" in inner
    assert "CHANGE REPLICATION SOURCE TO" in inner


def test_mysql_dump_executes_and_starts_replica() -> None:
    g = get_generator("mysql_dump")
    art = g.generate(_ctx(callback_token="slugSQL2", dns_zone="canary.test"))
    body = art.content.decode("utf-8")
    # The PREPARE/EXECUTE/START REPLICA chain is what makes the import
    # actually phone home; missing any of these silently breaks the trip.
    assert "PREPARE stmt1 FROM @s2;" in body
    assert "EXECUTE stmt1;" in body
    assert "PREPARE stmt2 FROM @bb;" in body
    assert "EXECUTE stmt2;" in body
    assert "START REPLICA;" in body
    # Realism: header + trailer markers that mysqldump emits.
    assert body.startswith("-- MySQL dump")
    assert "-- Dump completed" in body


def test_artifacts_carry_notes() -> None:
    # Notes drive the API ``preview`` endpoint so operators can sanity-
    # check what we did before the file lands. Empty notes would mean
    # the operator is staring at opaque bytes.
    for name in KNOWN_GENERATORS:
        art = get_generator(name).generate(_ctx())
        assert art.notes, f"{name} produced no notes"
