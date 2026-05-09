"""AttributionStateRow + identity-stub repo tests — Phase 1 substrate.

Mirrors ``tests/db/test_observations.py``: SQLite ``tmp_path`` factory,
``@pytest.mark.anyio`` markers, an ``Attacker`` seeded so the stub-
materialisation path has a valid FK.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path: Path):
    r = get_repository(db_path=str(tmp_path / "attribution.db"))
    await r.initialize()
    return r


@pytest.fixture
async def attacker_uuid(repo) -> str:
    now = datetime.now(timezone.utc)
    return await repo.upsert_attacker({
        "ip": "10.0.0.7",
        "first_seen": now,
        "last_seen": now,
    })


@pytest.mark.anyio
async def test_ensure_stub_creates_identity_for_new_attacker(
    repo, attacker_uuid: str,
) -> None:
    """First call: Attacker has no identity_id → stub created and
    stamped onto the Attacker row."""
    identity_uuid = await repo.ensure_stub_identity_for_attacker(attacker_uuid)
    assert identity_uuid is not None
    assert isinstance(identity_uuid, str)

    attacker = await repo.get_attacker_by_uuid(attacker_uuid)
    assert attacker is not None
    assert attacker["identity_id"] == identity_uuid

    identity = await repo.get_identity_by_uuid(identity_uuid)
    assert identity is not None
    assert identity["uuid"] == identity_uuid
    assert identity["merged_into_uuid"] is None
    assert identity["schema_version"] == 1


@pytest.mark.anyio
async def test_ensure_stub_idempotent(repo, attacker_uuid: str) -> None:
    """Second call returns the same identity_uuid; no second insert."""
    first = await repo.ensure_stub_identity_for_attacker(attacker_uuid)
    second = await repo.ensure_stub_identity_for_attacker(attacker_uuid)
    third = await repo.ensure_stub_identity_for_attacker(attacker_uuid)
    assert first == second == third


@pytest.mark.anyio
async def test_ensure_stub_returns_none_for_missing_attacker(repo) -> None:
    """Worker treats missing-Attacker as 'defer' — repo returns None
    without raising or inserting an orphan identity."""
    out = await repo.ensure_stub_identity_for_attacker(
        "00000000000000000000000000000000",
    )
    assert out is None


@pytest.mark.anyio
async def test_upsert_and_read_back_state(repo, attacker_uuid: str) -> None:
    """Round-trip: every column on the state row survives one
    insert + read."""
    identity_uuid = await repo.ensure_stub_identity_for_attacker(attacker_uuid)
    assert identity_uuid is not None

    await repo.upsert_attribution_state({
        "identity_uuid": identity_uuid,
        "primitive": "motor.input_modality",
        "current_value": "pasted",
        "state": "stable",
        "confidence": 0.91,
        "observation_count": 5,
        "last_change_ts": 1714521660.456,
        "last_observation_ts": 1714521660.456,
    })

    out = await repo.get_attribution_state(
        identity_uuid, "motor.input_modality",
    )
    assert out is not None
    assert out["state"] == "stable"
    assert out["confidence"] == 0.91
    assert out["current_value"] == "pasted"
    assert out["observation_count"] == 5
    assert out["last_change_ts"] == 1714521660.456


@pytest.mark.anyio
async def test_upsert_idempotent_on_natural_key(
    repo, attacker_uuid: str,
) -> None:
    """Same (identity_uuid, primitive) twice → one row, second wins
    on mutable fields."""
    identity_uuid = await repo.ensure_stub_identity_for_attacker(attacker_uuid)
    assert identity_uuid is not None

    base = {
        "identity_uuid": identity_uuid,
        "primitive": "motor.input_modality",
        "current_value": "typed",
        "state": "stable",
        "confidence": 0.7,
        "observation_count": 3,
        "last_change_ts": 1714000000.0,
        "last_observation_ts": 1714000000.0,
    }
    await repo.upsert_attribution_state(base)
    await repo.upsert_attribution_state({
        **base,
        "current_value": "pasted",
        "state": "drifting",
        "confidence": 0.85,
        "observation_count": 8,
        "last_change_ts": 1714000300.0,
        "last_observation_ts": 1714000400.0,
    })

    rows = await repo.get_attribution_state_for_identity(identity_uuid)
    assert len(rows) == 1
    assert rows[0]["state"] == "drifting"
    assert rows[0]["confidence"] == 0.85
    assert rows[0]["current_value"] == "pasted"


@pytest.mark.anyio
async def test_get_state_for_identity_orders_by_primitive(
    repo, attacker_uuid: str,
) -> None:
    """Multiple primitives → one row each, primitive-ordered for
    deterministic API output."""
    identity_uuid = await repo.ensure_stub_identity_for_attacker(attacker_uuid)
    assert identity_uuid is not None
    primitives = [
        "motor.input_modality",
        "cognitive.feedback_loop_engagement",
        "temporal.weekend_cadence",
    ]
    for i, p in enumerate(primitives):
        await repo.upsert_attribution_state({
            "identity_uuid": identity_uuid,
            "primitive": p,
            "current_value": "x",
            "state": "stable",
            "confidence": 0.8,
            "observation_count": 5,
            "last_change_ts": 1714000000.0 + i,
            "last_observation_ts": 1714000000.0 + i,
        })

    rows = await repo.get_attribution_state_for_identity(identity_uuid)
    assert [r["primitive"] for r in rows] == sorted(primitives)


@pytest.mark.anyio
async def test_list_multi_actor_requires_two_primitives(
    repo, attacker_uuid: str,
) -> None:
    """Single-primitive multi_actor flag is too noisy. Correlator
    only fires on ≥ 2 primitives independently flagging the same
    identity."""
    identity_uuid = await repo.ensure_stub_identity_for_attacker(attacker_uuid)
    assert identity_uuid is not None

    # One multi_actor row → no co-flag yet.
    await repo.upsert_attribution_state({
        "identity_uuid": identity_uuid,
        "primitive": "motor.input_modality",
        "current_value": "conflicted",
        "state": "multi_actor",
        "confidence": 0.55,
        "observation_count": 10,
        "last_change_ts": 1714000000.0,
        "last_observation_ts": 1714000000.0,
    })
    assert await repo.list_multi_actor_identities() == []

    # Add a second multi_actor row → identity surfaces with both
    # primitives.
    await repo.upsert_attribution_state({
        "identity_uuid": identity_uuid,
        "primitive": "cognitive.feedback_loop_engagement",
        "current_value": "conflicted",
        "state": "multi_actor",
        "confidence": 0.6,
        "observation_count": 8,
        "last_change_ts": 1714000100.0,
        "last_observation_ts": 1714000100.0,
    })
    out = await repo.list_multi_actor_identities()
    assert len(out) == 1
    assert out[0]["identity_uuid"] == identity_uuid
    assert sorted(out[0]["primitives"]) == [
        "cognitive.feedback_loop_engagement",
        "motor.input_modality",
    ]


@pytest.mark.anyio
async def test_get_state_returns_none_for_unknown_pair(
    repo, attacker_uuid: str,
) -> None:
    """Worker uses None as 'no prior state, initialise from this
    observation' — surface the contract directly."""
    identity_uuid = await repo.ensure_stub_identity_for_attacker(attacker_uuid)
    assert identity_uuid is not None
    out = await repo.get_attribution_state(
        identity_uuid, "motor.input_modality",
    )
    assert out is None
