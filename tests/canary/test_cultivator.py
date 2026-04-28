"""Realism-driven canary cultivation.

Stage 7 of the realism migration: the orchestrator's planner picks a
canary content_class ~3% of file ticks; the cultivator turns that into
a CanaryArtifact + persisted CanaryToken row.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from decnet.canary.cultivator import cultivate
from decnet.realism.taxonomy import ContentClass, Plan
from decnet.web.db.sqlite.repository import SQLiteRepository


@pytest_asyncio.fixture
async def repo(tmp_path):
    r = SQLiteRepository(db_path=str(tmp_path / "decnet.db"))
    await r.initialize()
    yield r
    await r.engine.dispose()


def _plan(cls: ContentClass, persona: str = "admin") -> Plan:
    return Plan(
        decky_uuid="d1",
        decky_name="alpha",
        persona=persona,
        content_class=cls,
        action="create",
        target_path="",
        mtime=datetime(2026, 4, 27, 11, 30, tzinfo=timezone.utc),
        body_hint=None,
    )


@pytest.mark.asyncio
async def test_cultivate_records_canary_token_row(repo, monkeypatch):
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.example.test")
    monkeypatch.setenv("DECNET_CANARY_DNS_ZONE", "canary.example.test")

    artifact = await cultivate(
        _plan(ContentClass.CANARY_GIT_CONFIG), repo,
    )
    assert artifact.path == "/home/admin/.git/config"
    assert artifact.content
    # Token row landed and the slug round-trips through the slug index.
    rows = await repo.list_canary_tokens(decky_name="alpha")
    assert len(rows) == 1
    assert rows[0]["generator"] == "git_config"
    assert rows[0]["placement_path"] == "/home/admin/.git/config"
    assert rows[0]["callback_token"] in artifact.content.decode("utf-8")


@pytest.mark.asyncio
async def test_cultivate_persists_path_for_each_class(repo, monkeypatch):
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.example.test")
    monkeypatch.setenv("DECNET_CANARY_DNS_ZONE", "canary.example.test")

    classes_and_paths = {
        ContentClass.CANARY_AWS_CREDS: "/home/admin/.aws/credentials",
        ContentClass.CANARY_ENV_FILE: "/home/admin/app/.env",
        ContentClass.CANARY_GIT_CONFIG: "/home/admin/.git/config",
        ContentClass.CANARY_SSH_KEY: "/home/admin/.ssh/id_rsa",
        ContentClass.CANARY_HONEYDOC: "/home/admin/Documents/notes.html",
        ContentClass.CANARY_MYSQL_DUMP: "/var/backups/db_backup.sql",
    }
    for cls, expected in classes_and_paths.items():
        artifact = await cultivate(_plan(cls), repo)
        assert artifact.path == expected, (
            f"{cls.value!r} planted at {artifact.path!r}, want {expected!r}"
        )


@pytest.mark.asyncio
async def test_cultivate_rejects_non_canary_class(repo):
    with pytest.raises(ValueError, match="non-canary"):
        await cultivate(_plan(ContentClass.NOTE), repo)


@pytest.mark.asyncio
async def test_cultivate_persona_login_normalisation(repo, monkeypatch):
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.example.test")
    monkeypatch.setenv("DECNET_CANARY_DNS_ZONE", "canary.example.test")
    artifact = await cultivate(
        _plan(ContentClass.CANARY_AWS_CREDS, persona="John Smith"), repo,
    )
    # Spaces collapsed to lowercase login, same convention as the
    # realism namer's _home() function.
    assert artifact.path == "/home/johnsmith/.aws/credentials"


@pytest.mark.asyncio
async def test_cultivate_artifact_does_not_leak_decnet_string(repo, monkeypatch):
    """Stealth contract (per feedback_stealth.md): a planted canary's
    bytes must never carry the DECNET literal — that would tell an
    attacker the file is a honeypot trap."""
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.example.test")
    monkeypatch.setenv("DECNET_CANARY_DNS_ZONE", "canary.example.test")
    for cls in (
        ContentClass.CANARY_AWS_CREDS,
        ContentClass.CANARY_GIT_CONFIG,
        ContentClass.CANARY_ENV_FILE,
        ContentClass.CANARY_SSH_KEY,
    ):
        artifact = await cultivate(_plan(cls), repo)
        body = artifact.content.decode("utf-8", errors="replace")
        assert "decnet" not in body.lower(), (
            f"{cls.value!r} body leaked 'decnet': "
            f"{body[:120]!r}"
        )


@pytest.mark.asyncio
async def test_cultivate_records_kind_per_generator(repo, monkeypatch):
    """The token row's ``kind`` reflects the trip surface of the
    underlying generator: HTTP slug callback, DNS resolution, or
    passive bait. The canary worker uses ``kind`` to route incoming
    callbacks; a wrong kind means the trip won't attribute correctly."""
    monkeypatch.setenv("DECNET_CANARY_HTTP_BASE", "https://canary.example.test")
    monkeypatch.setenv("DECNET_CANARY_DNS_ZONE", "canary.example.test")
    cases = [
        (ContentClass.CANARY_AWS_CREDS, "aws_passive"),
        (ContentClass.CANARY_ENV_FILE, "http"),
        (ContentClass.CANARY_GIT_CONFIG, "http"),
        (ContentClass.CANARY_HONEYDOC, "http"),
        (ContentClass.CANARY_HONEYDOC_DOCX, "http"),
        (ContentClass.CANARY_HONEYDOC_PDF, "http"),
        (ContentClass.CANARY_SSH_KEY, "dns"),
        (ContentClass.CANARY_MYSQL_DUMP, "dns"),
    ]
    for cls, expected_kind in cases:
        await cultivate(_plan(cls, persona=f"p-{cls.value}"), repo)
    rows = await repo.list_canary_tokens(decky_name="alpha")
    by_gen = {r["generator"]: r["kind"] for r in rows}
    for cls, expected_kind in cases:
        from decnet.canary.cultivator import _CLASS_TO_GENERATOR
        gen = _CLASS_TO_GENERATOR[cls]
        assert by_gen[gen] == expected_kind, (
            f"{cls.value!r} → generator {gen!r} got kind={by_gen[gen]!r}, "
            f"want {expected_kind!r}"
        )
