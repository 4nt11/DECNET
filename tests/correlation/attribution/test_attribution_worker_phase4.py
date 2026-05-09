"""Phase 4 — end-to-end worker wiring.

Observation event → stub identity → load series → merger → upsert
state → emit ``attribution.profile.state_changed`` on transition.

Phase 1 covered stub-only wiring; this file pins the merger /
persist / publish path against an in-memory SQLite + FakeBus.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.correlation import attribution_worker as _aw
from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path: Path):
    r = get_repository(db_path=str(tmp_path / "phase4.db"))
    await r.initialize()
    return r


@pytest.fixture
async def attacker_uuid(repo) -> str:
    now = datetime.now(timezone.utc)
    return await repo.upsert_attacker({
        "ip": "10.0.0.5",
        "first_seen": now,
        "last_seen": now,
    })


def _envelope(
    *,
    primitive: str,
    value: Any,
    attacker_uuid: str,
    evidence_ref: str,
    ts: float,
    confidence: float = 0.9,
) -> dict[str, Any]:
    return {
        "id": f"obs-{evidence_ref}-{primitive}",
        "primitive": primitive,
        "value": value,
        "confidence": confidence,
        "window_start_ts": ts,
        "window_end_ts": ts,
        "source": "test",
        "evidence_ref": evidence_ref,
        "envelope_v": 1,
        "ts": ts,
        "attacker_uuid": attacker_uuid,
    }


def _bus_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Worker reads payload via getattr(.payload, fallback to dict)."""
    return payload


async def _seed_observations(
    repo, attacker_uuid: str, primitive: str, values: list[Any],
    *, start_ts: float = 1714000000.0,
) -> None:
    for i, v in enumerate(values):
        ts = start_ts + i * 60.0
        # ts in evidence_ref so repeated calls with overlapping i but
        # distinct start_ts produce distinct rows.
        await repo.upsert_observation(_envelope(
            primitive=primitive,
            value=v,
            attacker_uuid=attacker_uuid,
            evidence_ref=f"shard:test#{primitive}-{ts}",
            ts=ts,
        ))


@pytest.mark.anyio
async def test_handler_writes_unknown_below_threshold(
    repo, attacker_uuid: str,
) -> None:
    """Two observations for one primitive → state row written with
    state='unknown' (< MIN_OBSERVATIONS_FOR_STATE)."""
    bus = FakeBus()
    await bus.connect()
    await _seed_observations(
        repo, attacker_uuid, "motor.input_modality", ["typed", "typed"],
    )
    await _aw.handle_observation_event(bus, repo, _bus_event({
        "attacker_uuid": attacker_uuid,
        "primitive": "motor.input_modality",
    }))

    attacker = await repo.get_attacker_by_uuid(attacker_uuid)
    assert attacker is not None
    identity_uuid = attacker["identity_id"]
    state = await repo.get_attribution_state(
        identity_uuid, "motor.input_modality",
    )
    assert state is not None
    assert state["state"] == "unknown"
    await bus.close()


@pytest.mark.anyio
async def test_handler_emits_state_changed_on_transition(
    repo, attacker_uuid: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """As observations cross MIN_OBSERVATIONS_FOR_STATE, the worker
    fires <new>→unknown then unknown→stable; idempotent re-runs in
    between fire nothing."""
    bus = FakeBus()
    await bus.connect()

    captured: list[dict[str, Any]] = []

    async def _capture(_bus, topic, payload, *, event_type=""):
        captured.append({"topic": topic, "payload": payload})

    monkeypatch.setattr(_aw, "publish_safely", _capture)

    for i in range(5):
        await _seed_observations(
            repo, attacker_uuid, "motor.input_modality",
            ["typed"], start_ts=1714000000.0 + i * 60.0,
        )
        await _aw.handle_observation_event(bus, repo, _bus_event({
            "attacker_uuid": attacker_uuid,
            "primitive": "motor.input_modality",
        }))

    states_seen = [c["payload"]["new_state"] for c in captured]
    assert states_seen == ["unknown", "stable"], states_seen
    # The transition payload carries old + new + the observation that
    # caused the flip.
    assert captured[0]["payload"]["old_state"] is None
    assert captured[1]["payload"]["old_state"] == "unknown"
    await bus.close()


@pytest.mark.anyio
async def test_handler_no_event_when_state_unchanged(
    repo, attacker_uuid: str,
) -> None:
    """Re-running the merger over an unchanged observation set must
    not emit a duplicate state_changed event (loop-prevention)."""
    bus = FakeBus()
    await bus.connect()

    captured: list[Any] = []
    sub = bus.subscribe(
        _topics.attribution(_topics.ATTRIBUTION_PROFILE_STATE_CHANGED),
    )

    import asyncio

    async def drain() -> None:
        try:
            async with sub:
                async for ev in sub:
                    captured.append(ev)
        except Exception:
            pass

    drain_task = asyncio.create_task(drain())
    await asyncio.sleep(0)

    await _seed_observations(
        repo, attacker_uuid, "motor.input_modality",
        ["typed"] * 5,
    )
    # First run: <new> → stable, fires event.
    await _aw.handle_observation_event(bus, repo, _bus_event({
        "attacker_uuid": attacker_uuid,
        "primitive": "motor.input_modality",
    }))
    await asyncio.sleep(0.05)
    first_count = len(captured)

    # Re-run with no new observations: state stays "stable", no event.
    for _ in range(3):
        await _aw.handle_observation_event(bus, repo, _bus_event({
            "attacker_uuid": attacker_uuid,
            "primitive": "motor.input_modality",
        }))
    await asyncio.sleep(0.05)

    drain_task.cancel()
    assert len(captured) == first_count, (
        "state didn't change; no additional events should fire"
    )
    await bus.close()


@pytest.mark.anyio
async def test_handler_locks_last_change_ts_when_unchanged(
    repo, attacker_uuid: str,
) -> None:
    """When the state doesn't change, last_change_ts must NOT advance —
    that's what tells the dashboard 'stable since X', not 'stable
    since most-recent-observation'."""
    bus = FakeBus()
    await bus.connect()
    await _seed_observations(
        repo, attacker_uuid, "motor.input_modality",
        ["typed"] * 5,
    )
    await _aw.handle_observation_event(bus, repo, _bus_event({
        "attacker_uuid": attacker_uuid,
        "primitive": "motor.input_modality",
    }))
    attacker = await repo.get_attacker_by_uuid(attacker_uuid)
    assert attacker is not None
    identity_uuid = attacker["identity_id"]
    first = await repo.get_attribution_state(
        identity_uuid, "motor.input_modality",
    )
    assert first is not None
    locked_ts = first["last_change_ts"]

    # Add another stable observation, re-run.
    await _seed_observations(
        repo, attacker_uuid, "motor.input_modality",
        ["typed"], start_ts=1714010000.0,
    )
    await _aw.handle_observation_event(bus, repo, _bus_event({
        "attacker_uuid": attacker_uuid,
        "primitive": "motor.input_modality",
    }))
    second = await repo.get_attribution_state(
        identity_uuid, "motor.input_modality",
    )
    assert second is not None
    assert second["last_change_ts"] == locked_ts
    # last_observation_ts DID advance.
    assert second["last_observation_ts"] > locked_ts
    await bus.close()


@pytest.mark.anyio
async def test_handler_routes_numeric_primitive(
    repo, attacker_uuid: str,
) -> None:
    """Worker dispatches to the numeric merger when the primitive
    registry kind is NUMERIC."""
    bus = FakeBus()
    await bus.connect()
    # toolchain.c2.beacon_interval_ms is registered NUMERIC in BEHAVE.
    primitive = "toolchain.c2.beacon_interval_ms"
    await _seed_observations(
        repo, attacker_uuid, primitive,
        [5000.0, 5050.0, 4980.0, 5020.0, 5010.0],
    )
    await _aw.handle_observation_event(bus, repo, _bus_event({
        "attacker_uuid": attacker_uuid,
        "primitive": primitive,
    }))
    attacker = await repo.get_attacker_by_uuid(attacker_uuid)
    assert attacker is not None
    state = await repo.get_attribution_state(
        attacker["identity_id"], primitive,
    )
    assert state is not None
    # Numeric merger returns a smoothed mean, not a string.
    assert isinstance(state["current_value"], float)
    assert state["state"] == "stable"
    await bus.close()
