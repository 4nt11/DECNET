# SPDX-License-Identifier: AGPL-3.0-or-later
"""E.4.a — TTP backfill CLI replays history through the live tagger.

Pins the contract from ``development/TTP_TAGGING.md`` §"E.4 Out-of-band
tasks": ``decnet ttp-backfill --since-days N`` walks
:class:`Attacker.commands` and :class:`CanaryTrigger` history,
dispatches each row through :class:`CompositeTagger`, persists tags via
``insert_tags`` (idempotent) and **does NOT publish** to the bus —
historical replay must not re-trigger SIEM/webhook fan-out on
already-attributed events.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from decnet.cli.ttp import (
    _BACKFILL_SOURCES,
    _backfill,
    _resolve_sources,
)
from decnet.ttp.base import Tagger, TaggerEvent
from decnet.web.db.models.ttp import TTPTag


# ── Test doubles ────────────────────────────────────────────────────


class _RecordingTagger(Tagger):
    """Records every TaggerEvent and returns one TTPTag per call.

    The composite is bypassed entirely — the backfill driver is
    correct iff it emits the right TaggerEvent shape per source row.
    """

    name = "recording"
    HANDLES = frozenset({"command", "canary_fingerprint"})

    def __init__(self) -> None:
        self.events: list[TaggerEvent] = []

    async def tag(self, event: TaggerEvent) -> list[TTPTag]:
        self.events.append(event)
        return [TTPTag(
            uuid=f"tag-{event.source_kind}-{event.source_id}",
            source_kind=event.source_kind,
            source_id=event.source_id,
            attacker_uuid=event.attacker_uuid,
            identity_uuid=event.identity_uuid,
            session_id=event.session_id,
            decky_id=event.decky_id,
            tactic="TA0002",
            technique_id="T1059",
            sub_technique_id=None,
            confidence=0.9,
            rule_id="R0001",
            rule_version=1,
            evidence={},
            attack_release="v15.1",
            created_at=datetime.now(tz=timezone.utc),
        )]


class _FakeRepo:
    def __init__(
        self,
        attackers_with_commands: list[tuple[Any, list[dict[str, Any]]]],
        canary_triggers: list[Any],
    ) -> None:
        self._attackers = attackers_with_commands
        self._triggers = canary_triggers
        self.insert_calls: int = 0
        self._seen: set[str] = set()

    async def iter_attacker_commands_since(self, since: datetime):  # noqa: ANN201
        for pair in self._attackers:
            yield pair

    async def iter_canary_triggers_since(self, since: datetime):  # noqa: ANN201
        for t in self._triggers:
            yield t

    async def insert_tags(self, rows: list[TTPTag]) -> int:
        self.insert_calls += 1
        new = [r for r in rows if r.uuid not in self._seen]
        for r in new:
            self._seen.add(r.uuid)
        return len(new)


def _make_attacker(uuid: str = "att-1", identity_id: str | None = "id-1") -> Any:
    a = MagicMock()
    a.uuid = uuid
    a.identity_id = identity_id
    return a


def _make_trigger(uuid: str, src_ip: str = "1.2.3.4") -> Any:
    t = MagicMock()
    t.uuid = uuid
    t.token_uuid = "tok-1"
    t.src_ip = src_ip
    t.user_agent = "curl/7.88.1"
    t.request_path = "/x"
    t.dns_qname = None
    t.attacker_id = "att-1"
    t.headers = lambda: {"x-forwarded-for": "9.9.9.9"}
    return t


# ── Surface ─────────────────────────────────────────────────────────


def test_backfill_sources_constant() -> None:
    assert _BACKFILL_SOURCES == ("command", "canary", "all")


def test_resolve_sources_all_expands() -> None:
    assert _resolve_sources("all") == ("command", "canary")
    assert _resolve_sources("command") == ("command",)
    assert _resolve_sources("canary") == ("canary",)


# ── Driver behaviour ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_backfill_command_source_emits_one_event_per_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tagger = _RecordingTagger()
    monkeypatch.setattr(
        "decnet.cli.ttp.get_tagger", lambda: tagger,
    )
    attacker = _make_attacker()
    repo = _FakeRepo(
        attackers_with_commands=[(attacker, [
            {"id": "cmd-a", "command_text": "whoami"},
            {"id": "cmd-b", "command_text": "id"},
            {"id": "cmd-c", "command_text": "uname -a"},
        ])],
        canary_triggers=[],
    )
    await _backfill(
        repo,
        cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
        sources=("command",),
        dry_run=False,
        batch_size=10,
    )
    kinds = [e.source_kind for e in tagger.events]
    assert kinds == ["command", "command", "command"]
    assert [e.source_id for e in tagger.events] == ["cmd-a", "cmd-b", "cmd-c"]
    assert [e.payload["command_text"] for e in tagger.events] == [
        "whoami", "id", "uname -a",
    ]
    assert repo.insert_calls == 1


@pytest.mark.asyncio
async def test_backfill_is_idempotent_on_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tagger = _RecordingTagger()
    monkeypatch.setattr("decnet.cli.ttp.get_tagger", lambda: tagger)
    attacker = _make_attacker()
    repo = _FakeRepo(
        attackers_with_commands=[(attacker, [
            {"id": "cmd-a", "command_text": "whoami"},
        ])],
        canary_triggers=[],
    )
    await _backfill(repo, cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    sources=("command",), dry_run=False, batch_size=10)
    # Run twice — second pass writes zero rows because INSERT OR IGNORE
    # collapses on the deterministic compute_tag_uuid PK.
    await _backfill(repo, cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    sources=("command",), dry_run=False, batch_size=10)
    # Same set of UUIDs across both passes; second pass yields 0.
    assert len(repo._seen) == 1


@pytest.mark.asyncio
async def test_backfill_dry_run_skips_insert_tags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tagger = _RecordingTagger()
    monkeypatch.setattr("decnet.cli.ttp.get_tagger", lambda: tagger)
    attacker = _make_attacker()
    repo = _FakeRepo(
        attackers_with_commands=[(attacker, [
            {"id": "cmd-a", "command_text": "whoami"},
        ])],
        canary_triggers=[],
    )
    await _backfill(
        repo, cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
        sources=("command",), dry_run=True, batch_size=10,
    )
    assert repo.insert_calls == 0
    # Tagger was still invoked — the dry-run only skips persistence.
    assert len(tagger.events) == 1


@pytest.mark.asyncio
async def test_backfill_canary_source_emits_canary_fingerprint_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tagger = _RecordingTagger()
    monkeypatch.setattr("decnet.cli.ttp.get_tagger", lambda: tagger)
    repo = _FakeRepo(
        attackers_with_commands=[],
        canary_triggers=[_make_trigger("trig-1"), _make_trigger("trig-2")],
    )
    await _backfill(
        repo, cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
        sources=("canary",), dry_run=False, batch_size=10,
    )
    assert [e.source_kind for e in tagger.events] == [
        "canary_fingerprint", "canary_fingerprint",
    ]
    assert [e.source_id for e in tagger.events] == ["trig-1", "trig-2"]
    assert tagger.events[0].payload["src_ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_backfill_does_not_publish_to_bus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The backfill path must never touch the bus — no SIEM re-fire."""
    tagger = _RecordingTagger()
    monkeypatch.setattr("decnet.cli.ttp.get_tagger", lambda: tagger)
    publish_called = False

    def _explode(*_a: object, **_kw: object) -> None:
        nonlocal publish_called
        publish_called = True

    # The CLI module must not import the bus publisher at all; this
    # guard catches any future drift.
    monkeypatch.setattr(
        "decnet.bus.publish.run_health_heartbeat", _explode, raising=False,
    )
    attacker = _make_attacker()
    repo = _FakeRepo(
        attackers_with_commands=[(attacker, [
            {"id": "cmd-a", "command_text": "whoami"},
        ])],
        canary_triggers=[],
    )
    await _backfill(
        repo, cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
        sources=("command",), dry_run=False, batch_size=10,
    )
    assert not publish_called


@pytest.mark.asyncio
async def test_backfill_command_skips_malformed_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tagger = _RecordingTagger()
    monkeypatch.setattr("decnet.cli.ttp.get_tagger", lambda: tagger)
    attacker = _make_attacker()
    repo = _FakeRepo(
        attackers_with_commands=[(attacker, [
            {"id": "cmd-a", "command_text": "whoami"},
            {"id": "cmd-b"},  # no command_text
            {"id": "cmd-c", "command_text": "id"},
        ])],
        canary_triggers=[],
    )
    await _backfill(
        repo, cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc),
        sources=("command",), dry_run=False, batch_size=10,
    )
    assert [e.source_id for e in tagger.events] == ["cmd-a", "cmd-c"]
