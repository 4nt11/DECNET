# SPDX-License-Identifier: AGPL-3.0-or-later
"""Scheduler.pick() — async, takes a repo-shaped object."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import pytest

from decnet.orchestrator.emailgen import scheduler
from decnet.realism import personas_pool as global_pool


@pytest.fixture(autouse=True)
def _reset_global_pool():
    global_pool.reset_cache()
    yield
    global_pool.reset_cache()


_PERSONAS_TWO = [
    {
        "name": "John Smith",
        "email": "john@corp.com",
        "role": "COO",
        "tone": "formal",
        "mannerisms": ["uses 'Best regards'"],
    },
    {
        "name": "Sarah Johnson",
        "email": "sarah@corp.com",
        "role": "PM",
        "tone": "direct",
        "mannerisms": ["uses bullets"],
    },
]


class _FakeRepo:
    """Minimal repo stub matching the methods scheduler.pick() uses."""

    def __init__(
        self,
        *,
        deckies: list[dict[str, Any]] | None = None,
        topologies: dict[str, dict[str, Any]] | None = None,
        threads: list[dict[str, Any]] | None = None,
    ):
        self.deckies = deckies or []
        self.topologies = topologies or {}
        self.threads = threads or []
        self.thread_calls = 0

    async def list_running_deckies(self):
        return self.deckies

    async def get_topology(self, topology_id: str):
        return self.topologies.get(topology_id)

    async def list_orchestrator_email_threads(self, *args, **kwargs):
        self.thread_calls += 1
        return list(self.threads)


def _decky(
    uuid="d1",
    name="mailhost",
    services=("imap",),
    topology_id="t1",
    source="topology",
):
    return {
        "uuid": uuid,
        "name": name,
        "services": list(services),
        "topology_id": topology_id,
        "source": source,
    }


def _topology(personas=_PERSONAS_TWO, language_default="en"):
    return {
        "id": "t1",
        "email_personas": json.dumps(personas),
        "language_default": language_default,
    }


@pytest.mark.asyncio
async def test_pick_no_mail_decky_returns_none():
    repo = _FakeRepo(deckies=[_decky(services=("ssh",))])
    assert await scheduler.pick(repo) is None


@pytest.mark.asyncio
async def test_pick_unknown_topology_returns_none():
    repo = _FakeRepo(deckies=[_decky()])
    # No topology row for "t1" — scheduler should bail.
    assert await scheduler.pick(repo) is None


@pytest.mark.asyncio
async def test_pick_topology_with_one_persona_returns_none():
    repo = _FakeRepo(
        deckies=[_decky()],
        topologies={"t1": _topology(personas=_PERSONAS_TWO[:1])},
    )
    assert await scheduler.pick(repo) is None


@pytest.mark.asyncio
async def test_pick_returns_action_for_valid_setup():
    repo = _FakeRepo(
        deckies=[_decky()],
        topologies={"t1": _topology()},
    )
    action = await scheduler.pick(repo, now=datetime(2026, 4, 26, 12, 0, 0))
    assert action is not None
    assert action.mail_decky_uuid == "d1"
    assert action.sender.email != action.recipient.email
    assert action.thread_id  # populated for both new and reply branches


@pytest.mark.asyncio
async def test_pick_active_hours_filter_kicks_in_at_midnight():
    repo = _FakeRepo(
        deckies=[_decky()],
        topologies={"t1": _topology()},
    )
    # Default active_hours is 09:00-18:00; midnight => everyone out of office.
    action = await scheduler.pick(repo, now=datetime(2026, 4, 26, 3, 0, 0))
    assert action is None


@pytest.mark.asyncio
async def test_pick_uses_pop3_decky_too():
    repo = _FakeRepo(
        deckies=[_decky(services=("pop3",))],
        topologies={"t1": _topology()},
    )
    action = await scheduler.pick(repo, now=datetime(2026, 4, 26, 12, 0, 0))
    assert action is not None


@pytest.mark.asyncio
async def test_pick_for_fleet_source_uses_global_pool(tmp_path, monkeypatch):
    """Fleet (MACVLAN/IPVLAN) mail decky has no parent topology row;
    personas come from the host-wide JSON file."""
    pool_file = tmp_path / "personas.json"
    pool_file.write_text(json.dumps(_PERSONAS_TWO))
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(pool_file))

    repo = _FakeRepo(
        deckies=[_decky(source="fleet", topology_id=None)],
        # No topology row — confirms we never walk back to the topology.
    )
    action = await scheduler.pick(repo, now=datetime(2026, 4, 26, 12, 0, 0))
    assert action is not None
    assert action.mail_decky_uuid == "d1"


@pytest.mark.asyncio
async def test_pick_for_shard_source_uses_global_pool(tmp_path, monkeypatch):
    """SWARM shards are non-topology too — same path as fleet."""
    pool_file = tmp_path / "personas.json"
    pool_file.write_text(json.dumps(_PERSONAS_TWO))
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(pool_file))

    repo = _FakeRepo(
        deckies=[_decky(source="shard", topology_id=None)],
    )
    action = await scheduler.pick(repo, now=datetime(2026, 4, 26, 12, 0, 0))
    assert action is not None


@pytest.mark.asyncio
async def test_pick_fleet_with_empty_global_pool_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(tmp_path / "missing.json"))
    repo = _FakeRepo(deckies=[_decky(source="fleet", topology_id=None)])
    assert await scheduler.pick(repo, now=datetime(2026, 4, 26, 12, 0, 0)) is None


@pytest.mark.asyncio
async def test_topology_personas_isolated_from_global_pool(tmp_path, monkeypatch):
    """A topology with its own personas must NOT leak into / pull from
    the global pool — per-topology richness is the whole point."""
    pool_file = tmp_path / "personas.json"
    pool_file.write_text(json.dumps([{
        "name": "Pool Persona",
        "email": "pool@corp.com",
        "role": "Pooler",
        "tone": "casual",
        "mannerisms": [],
    }]))
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(pool_file))

    repo = _FakeRepo(
        deckies=[_decky()],
        topologies={"t1": _topology()},  # topology has _PERSONAS_TWO
    )
    action = await scheduler.pick(repo, now=datetime(2026, 4, 26, 12, 0, 0))
    assert action is not None
    # The chosen sender + recipient must come from the topology's pool,
    # not the global one — pool@corp.com would be a leak.
    assert action.sender.email != "pool@corp.com"
    assert action.recipient.email != "pool@corp.com"


@pytest.mark.asyncio
async def test_pick_reply_chain_sets_in_reply_to():
    threads = [{
        "thread_id": "thr1",
        "message_id": "<old@corp.com>",
        "subject": "Q3 budget",
    }]
    repo = _FakeRepo(
        deckies=[_decky()],
        topologies={"t1": _topology()},
        threads=threads,
    )

    # Force the "reply" branch by stubbing the RNG: random() < 0.6 is True.
    class _Rng:
        def __init__(self):
            self.calls = 0

        def choice(self, seq):
            return seq[0]

        def random(self):
            return 0.0    # always reply

    action = await scheduler.pick(
        repo, rand=_Rng(), now=datetime(2026, 4, 26, 12, 0, 0),
    )
    assert action is not None
    assert action.is_reply is True
    assert action.parent_message_id == "<old@corp.com>"
    assert action.thread_id == "thr1"
    assert action.subject_hint == "Re: Q3 budget"
