# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ingester wiring for mal_hash + observed_attachments (DEBT-046).

Validates `_publish_email_received` against a stub repo + stub provider:

* Provider hit on any attachment hash → ``mal_hash_match=True`` on the bus payload
* Provider clean on every hash → ``mal_hash_match=False`` on the bus payload
* No attachments → field omitted from the payload entirely
* Every observed hash lands in ``observed_attachments`` with the verdict baked in
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from decnet.intel import factory as intel_factory


class _StubRepo:
    def __init__(self) -> None:
        self.observed: list[dict] = []
        self.get_attacker_uuid_by_ip = AsyncMock(return_value="atk-1")

    async def upsert_observed_attachment(self, **kwargs):
        self.observed.append(kwargs)
        return "obs-uuid"


class _StubBus:
    def __init__(self) -> None:
        self.published: list[dict] = []

    async def connect(self):
        return None

    async def close(self):
        return None


class _StubProvider:
    name = "malwarebazaar"

    def __init__(self, hits: set[str]):
        self._hits = hits

    async def is_known_bad(self, sha256: str) -> bool:
        return sha256 in self._hits


@pytest.fixture(autouse=True)
def _reset_factory():
    intel_factory._reset_mal_hash_provider_for_testing()
    yield
    intel_factory._reset_mal_hash_provider_for_testing()


@pytest.fixture
def patched_bus(monkeypatch):
    """Patch out the ingester's bus singleton so publishes capture
    instead of going to the wire."""
    captured: list[dict] = []

    async def _publish_safely(bus, topic, payload, *, event_type=None):
        captured.append({"topic": topic, "payload": payload, "event_type": event_type})

    def _get_bus(client_name=""):
        return _StubBus()

    from decnet.web import ingester as mod
    monkeypatch.setattr(mod, "publish_safely", _publish_safely)
    monkeypatch.setattr(mod, "get_bus", _get_bus)
    return captured


def _log_data() -> dict:
    return {
        "attacker_ip": "203.0.113.5",
        "decky": "decky-uuid",
        "service": "smtp",
    }


def _fields(*, attachments: list[dict] | None) -> dict:
    return {
        "msg_id": "<m1@x>",
        "subject": "Test",
        "from_hdr": "atk@evil.example",
        "mail_from": "atk@evil.example",
        "return_path": "atk@evil.example",
        "rcpt_to": "victim@corp.example",
        "x_mailer": "Outlook",
        "dkim_signed": 0,
        "spf_pass": 0,
        "urls_json": "[]",
        "attachments_json": json.dumps(attachments) if attachments is not None else "[]",
        "attachment_count": len(attachments) if attachments else 0,
        "body_simhash": "0123456789abcdef",
        "body_base64_bytes": 0,
        "html_smuggling": 0,
        "stored_as": "/spool/m1.eml",
        "sha256": "f" * 64,
    }


@pytest.mark.asyncio
async def test_known_bad_attachment_sets_mal_hash_match_true(patched_bus, monkeypatch):
    bad = "a" * 64
    clean = "b" * 64

    def _factory():
        return _StubProvider(hits={bad})

    monkeypatch.setattr(intel_factory, "get_mal_hash_provider", _factory)
    from decnet.web import ingester as mod
    monkeypatch.setattr(
        "decnet.intel.factory.get_mal_hash_provider", _factory,
    )

    repo = _StubRepo()
    await mod._publish_email_received(
        repo, _log_data(),
        _fields(attachments=[
            {"sha256": bad, "extension": "docx"},
            {"sha256": clean, "extension": "pdf"},
        ]),
    )

    assert len(patched_bus) == 1
    payload = patched_bus[0]["payload"]
    assert payload["mal_hash_match"] is True
    assert payload["attachment_sha256s"] == [bad, clean]

    # Both hashes recorded with their verdicts.
    by_hash = {o["sha256"]: o for o in repo.observed}
    assert by_hash[bad]["mal_hash_match"] is True
    assert by_hash[bad]["mal_hash_match_provider"] == "malwarebazaar"
    assert by_hash[clean]["mal_hash_match"] is False


@pytest.mark.asyncio
async def test_clean_attachments_sets_mal_hash_match_false(patched_bus, monkeypatch):
    clean = "c" * 64

    def _factory():
        return _StubProvider(hits=set())

    monkeypatch.setattr(intel_factory, "get_mal_hash_provider", _factory)
    monkeypatch.setattr(
        "decnet.intel.factory.get_mal_hash_provider", _factory,
    )

    from decnet.web import ingester as mod
    repo = _StubRepo()
    await mod._publish_email_received(
        repo, _log_data(),
        _fields(attachments=[{"sha256": clean, "extension": "pdf"}]),
    )

    payload = patched_bus[0]["payload"]
    assert payload["mal_hash_match"] is False
    assert len(repo.observed) == 1
    assert repo.observed[0]["mal_hash_match"] is False


@pytest.mark.asyncio
async def test_no_attachments_omits_mal_hash_match(patched_bus, monkeypatch):
    def _factory():
        return _StubProvider(hits=set())

    monkeypatch.setattr(intel_factory, "get_mal_hash_provider", _factory)
    monkeypatch.setattr(
        "decnet.intel.factory.get_mal_hash_provider", _factory,
    )

    from decnet.web import ingester as mod
    repo = _StubRepo()
    await mod._publish_email_received(
        repo, _log_data(), _fields(attachments=[]),
    )

    payload = patched_bus[0]["payload"]
    assert "mal_hash_match" not in payload
    assert repo.observed == []


@pytest.mark.asyncio
async def test_provider_unavailable_still_persists_hashes_without_verdict(
    patched_bus, monkeypatch,
):
    """If the provider factory returns None (intel disabled), the
    ingester must still write observations — DECNET is a platform; we
    keep the hashes regardless of whether anyone classified them."""
    def _factory():
        return None

    monkeypatch.setattr(intel_factory, "get_mal_hash_provider", _factory)
    monkeypatch.setattr(
        "decnet.intel.factory.get_mal_hash_provider", _factory,
    )

    from decnet.web import ingester as mod
    repo = _StubRepo()
    sha = "d" * 64
    await mod._publish_email_received(
        repo, _log_data(),
        _fields(attachments=[{"sha256": sha, "extension": "exe"}]),
    )

    payload = patched_bus[0]["payload"]
    # No provider → False on the bus (everything checked = clean), and
    # the row lands with mal_hash_match=None (no verdict).
    assert payload["mal_hash_match"] is False
    assert len(repo.observed) == 1
    assert repo.observed[0]["mal_hash_match"] is None
    assert repo.observed[0]["mal_hash_match_provider"] is None
