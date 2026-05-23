# SPDX-License-Identifier: AGPL-3.0-or-later
"""Picker policy tests for the orchestrator scheduler.

Stage-3 realism split:

* :func:`scheduler.pick` is now traffic-only — sync, returns
  :class:`TrafficAction` or ``None``.
* :func:`scheduler.pick_file` is async, takes a repo (for persona
  resolution), and returns a :class:`FileAction` driven by
  :func:`decnet.realism.planner.pick`.

Pre-realism behavior (one ``pick()`` returning either kind) is gone;
the orchestrator worker rolls per tick.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from decnet.orchestrator import scheduler


def _decky(
    uuid: str = "u1",
    name: str = "decky-01",
    ip: str | None = "10.0.0.1",
    services: list[str] | str = ("ssh",),
    *,
    source: str = "topology",
    topology_id: str | None = "t1",
) -> dict:
    return {
        "uuid": uuid,
        "name": name,
        "ip": ip,
        "services": list(services) if not isinstance(services, str) else services,
        "source": source,
        "topology_id": topology_id,
    }


# ---------------------------------------------------------------------------
# Sync pick() — traffic only.
# ---------------------------------------------------------------------------


def test_pick_returns_none_when_no_ssh_deckies():
    deckies = [
        _decky("u1", services=["http"]),
        _decky("u2", services=["smb"]),
    ]
    assert scheduler.pick(deckies) is None


def test_pick_returns_none_with_single_ssh_decky():
    # Traffic needs a pair; one decky alone can't generate inter-decky
    # SSH probes. Realism file actions reach this single decky via the
    # async pick_file() entry point instead.
    deckies = [_decky()]
    assert scheduler.pick(deckies) is None


def test_pick_returns_none_when_ssh_decky_has_no_ip():
    deckies = [_decky(ip=None)]
    assert scheduler.pick(deckies) is None


def test_pick_traffic_with_two_ssh_deckies():
    deckies = [
        _decky("u1", "decky-01", "10.0.0.1", ["ssh"]),
        _decky("u2", "decky-02", "10.0.0.2", ["ssh"]),
    ]
    for _ in range(20):
        action = scheduler.pick(deckies)
        assert isinstance(action, scheduler.TrafficAction)
        assert action.src_uuid != action.dst_uuid
        assert action.dst_ip in {"10.0.0.1", "10.0.0.2"}
        assert action.protocol == "ssh"


def test_pick_skips_non_deserialised_services():
    """If services is still a JSON string (defensive), the decky is excluded."""
    deckies = [_decky(services='["ssh"]')]
    assert scheduler.pick(deckies) is None


# ---------------------------------------------------------------------------
# Async pick_file() — realism-driven file actions.
# ---------------------------------------------------------------------------


_PERSONAS_TWO = [
    {
        "name": "admin",
        "email": "admin@corp.com",
        "role": "ops",
        "tone": "direct",
        "mannerisms": [],
        "active_hours": "00:00-00:00",  # always-on for predictability
    },
    {
        "name": "ubuntu",
        "email": "ubuntu@corp.com",
        "role": "service",
        "tone": "casual",
        "mannerisms": [],
        "active_hours": "00:00-00:00",
    },
]


class _FakeRepo:
    """Minimal repo with just the methods scheduler.pick_file needs."""

    def __init__(self, *, topologies=None, fleet_pool=None):
        self._topologies = topologies or {}
        # Fleet/global pool gets read via realism.personas_pool.load();
        # the test pins the pool path via env in fleet-source tests.

    async def get_topology(self, topology_id):
        return self._topologies.get(topology_id)


def _topology_row(personas):
    import json
    return {
        "id": "t1",
        "email_personas": json.dumps(personas),
        "language_default": "en",
    }


@pytest.mark.asyncio
async def test_pick_file_returns_none_when_no_ssh_deckies():
    repo = _FakeRepo(topologies={"t1": _topology_row(_PERSONAS_TWO)})
    deckies = [_decky(services=["http"])]
    assert await scheduler.pick_file(deckies, repo) is None


@pytest.mark.asyncio
async def test_pick_file_returns_none_when_topology_has_no_personas():
    repo = _FakeRepo(topologies={"t1": _topology_row([])})
    deckies = [_decky()]
    assert await scheduler.pick_file(deckies, repo) is None


@pytest.mark.asyncio
async def test_pick_file_produces_file_action_for_topology_decky():
    import random as _r
    repo = _FakeRepo(topologies={"t1": _topology_row(_PERSONAS_TWO)})
    deckies = [_decky()]
    # Pin the RNG so the 3% canary gate (stage 7) and 10% leave-alone
    # roll don't flake this test.  Seed 1 lands on a vanilla create.
    action = await scheduler.pick_file(
        deckies, repo,
        now=datetime(2026, 4, 27, 12, 0, tzinfo=timezone.utc),
        rand=_r.Random(1),
    )
    assert isinstance(action, scheduler.FileAction)
    assert action.dst_uuid == "u1"
    assert action.persona in {"admin", "ubuntu"}
    assert action.path.startswith("/")
    assert action.content
    assert action.mtime is not None
    # mtime must be in the past (the realism failure today is
    # wall-clock-now stamps).
    assert action.mtime < datetime(2026, 4, 27, 12, 0, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_pick_file_skips_decky_when_personas_outside_window():
    out_of_hours = [{**p, "active_hours": "01:00-02:00"} for p in _PERSONAS_TWO]
    repo = _FakeRepo(topologies={"t1": _topology_row(out_of_hours)})
    deckies = [_decky()]
    action = await scheduler.pick_file(
        deckies, repo,
        now=datetime(2026, 4, 27, 12, 0, tzinfo=timezone.utc),
    )
    assert action is None


@pytest.mark.asyncio
async def test_pick_file_uses_global_pool_for_fleet_source(tmp_path, monkeypatch):
    import json
    import random as _r
    pool = tmp_path / "personas.json"
    pool.write_text(json.dumps(_PERSONAS_TWO))
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(pool))

    # Reset the global cache so the new pool path takes effect.
    from decnet.realism import personas_pool
    personas_pool.reset_cache()

    repo = _FakeRepo()  # no topology rows — fleet path
    deckies = [_decky(source="fleet", topology_id=None)]

    # Pin the RNG so the canary / leave-alone rolls don't flake.
    action = await scheduler.pick_file(
        deckies, repo,
        now=datetime(2026, 4, 27, 12, 0, tzinfo=timezone.utc),
        rand=_r.Random(1),
    )
    assert isinstance(action, scheduler.FileAction)
    assert action.dst_uuid == "u1"
