# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 5 — cross-primitive multi_actor correlator.

Periodic tick over attribution_state rows; fires
``attribution.profile.multi_actor_suspected`` when ≥ 2 primitives flag
the same identity. Dedup keeps it from spamming on every tick.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from decnet.bus.fake import FakeBus
from decnet.correlation import attribution_worker as _aw
from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path: Path):
    r = get_repository(db_path=str(tmp_path / "ma.db"))
    await r.initialize()
    return r


async def _seed_identity(repo, ip: str = "10.0.0.42") -> str:
    now = datetime.now(timezone.utc)
    auid = await repo.upsert_attacker({
        "ip": ip, "first_seen": now, "last_seen": now,
    })
    iuid = await repo.ensure_stub_identity_for_attacker(auid)
    assert iuid is not None
    return iuid


async def _set_state(
    repo, identity_uuid: str, primitive: str, state: str,
) -> None:
    await repo.upsert_attribution_state({
        "identity_uuid": identity_uuid,
        "primitive": primitive,
        "current_value": "x",
        "state": state,
        "confidence": 0.55,
        "observation_count": 10,
        "last_change_ts": 1714000000.0,
        "last_observation_ts": 1714000000.0,
    })


@pytest.mark.anyio
async def test_no_event_for_single_primitive_multi_actor(
    repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One primitive flagged multi_actor on its own is too noisy
    (flapping primitive, flaky network). The correlator must not
    fire."""
    bus = FakeBus(); await bus.connect()
    captured: list[dict[str, Any]] = []

    async def cap(_b, t, p, *, event_type=""):
        captured.append({"topic": t, "payload": p})
    monkeypatch.setattr(_aw, "publish_safely", cap)

    iuid = await _seed_identity(repo)
    await _set_state(repo, iuid, "motor.input_modality", "multi_actor")

    fired = await _aw.tick_multi_actor(bus, repo, {})
    assert fired == 0
    assert captured == []
    await bus.close()


@pytest.mark.anyio
async def test_event_fires_when_two_primitives_co_flag(
    repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = FakeBus(); await bus.connect()
    captured: list[dict[str, Any]] = []

    async def cap(_b, t, p, *, event_type=""):
        captured.append({"topic": t, "payload": p})
    monkeypatch.setattr(_aw, "publish_safely", cap)

    iuid = await _seed_identity(repo)
    await _set_state(repo, iuid, "motor.input_modality", "multi_actor")
    await _set_state(repo, iuid, "cognitive.feedback_loop_engagement", "multi_actor")

    fired = await _aw.tick_multi_actor(bus, repo, {})
    assert fired == 1
    assert len(captured) == 1
    payload = captured[0]["payload"]
    assert payload["identity_uuid"] == iuid
    assert sorted(payload["primitives"]) == [
        "cognitive.feedback_loop_engagement",
        "motor.input_modality",
    ]
    assert payload["confidence"] <= 0.6
    await bus.close()


@pytest.mark.anyio
async def test_dedup_no_refire_on_unchanged_primitive_set(
    repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same identity, same primitive set across two ticks → fire
    once. The correlator must dedup so the SIEM channel doesn't
    drown in repeats."""
    bus = FakeBus(); await bus.connect()
    captured: list[dict[str, Any]] = []

    async def cap(_b, t, p, *, event_type=""):
        captured.append({"topic": t, "payload": p})
    monkeypatch.setattr(_aw, "publish_safely", cap)

    iuid = await _seed_identity(repo)
    await _set_state(repo, iuid, "motor.input_modality", "multi_actor")
    await _set_state(repo, iuid, "cognitive.feedback_loop_engagement", "multi_actor")

    last_fired: dict[str, frozenset[str]] = {}
    fired1 = await _aw.tick_multi_actor(bus, repo, last_fired)
    fired2 = await _aw.tick_multi_actor(bus, repo, last_fired)
    fired3 = await _aw.tick_multi_actor(bus, repo, last_fired)

    assert fired1 == 1
    assert fired2 == 0
    assert fired3 == 0
    assert len(captured) == 1
    await bus.close()


@pytest.mark.anyio
async def test_refires_when_primitive_set_grows(
    repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A third primitive joining the multi_actor set is new
    information — re-emit so subscribers see the expanded
    evidence."""
    bus = FakeBus(); await bus.connect()
    captured: list[dict[str, Any]] = []

    async def cap(_b, t, p, *, event_type=""):
        captured.append({"topic": t, "payload": p})
    monkeypatch.setattr(_aw, "publish_safely", cap)

    iuid = await _seed_identity(repo)
    await _set_state(repo, iuid, "motor.input_modality", "multi_actor")
    await _set_state(repo, iuid, "cognitive.feedback_loop_engagement", "multi_actor")

    last_fired: dict[str, frozenset[str]] = {}
    await _aw.tick_multi_actor(bus, repo, last_fired)
    assert len(captured) == 1

    # Add a third primitive.
    await _set_state(repo, iuid, "temporal.weekend_cadence", "multi_actor")
    await _aw.tick_multi_actor(bus, repo, last_fired)

    assert len(captured) == 2
    # Latest payload carries all three.
    assert len(captured[1]["payload"]["primitives"]) == 3
    await bus.close()


@pytest.mark.anyio
async def test_rearms_when_primitives_drop_below_threshold(
    repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If an identity's multi_actor count falls below 2, the
    correlator should evict it from the dedup map so a future
    re-flap re-fires."""
    bus = FakeBus(); await bus.connect()
    captured: list[dict[str, Any]] = []

    async def cap(_b, t, p, *, event_type=""):
        captured.append({"topic": t, "payload": p})
    monkeypatch.setattr(_aw, "publish_safely", cap)

    iuid = await _seed_identity(repo)
    await _set_state(repo, iuid, "motor.input_modality", "multi_actor")
    await _set_state(repo, iuid, "cognitive.feedback_loop_engagement", "multi_actor")

    last_fired: dict[str, frozenset[str]] = {}
    await _aw.tick_multi_actor(bus, repo, last_fired)
    assert len(captured) == 1
    assert iuid in last_fired

    # One primitive recovers to stable; identity drops below threshold.
    await _set_state(repo, iuid, "motor.input_modality", "stable")
    await _aw.tick_multi_actor(bus, repo, last_fired)
    assert iuid not in last_fired

    # Re-flap: same primitives flag again. Dedup should NOT block.
    await _set_state(repo, iuid, "motor.input_modality", "multi_actor")
    await _aw.tick_multi_actor(bus, repo, last_fired)
    assert len(captured) == 2
    await bus.close()


@pytest.mark.anyio
async def test_independent_dedup_per_identity(
    repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two identities, both co-flagged → both fire on the same tick."""
    bus = FakeBus(); await bus.connect()
    captured: list[dict[str, Any]] = []

    async def cap(_b, t, p, *, event_type=""):
        captured.append({"topic": t, "payload": p})
    monkeypatch.setattr(_aw, "publish_safely", cap)

    iuid_a = await _seed_identity(repo, ip="10.0.0.1")
    iuid_b = await _seed_identity(repo, ip="10.0.0.2")
    for iuid in (iuid_a, iuid_b):
        await _set_state(repo, iuid, "motor.input_modality", "multi_actor")
        await _set_state(
            repo, iuid, "cognitive.feedback_loop_engagement", "multi_actor",
        )

    fired = await _aw.tick_multi_actor(bus, repo, {})
    assert fired == 2
    seen = {c["payload"]["identity_uuid"] for c in captured}
    assert seen == {iuid_a, iuid_b}
    await bus.close()
