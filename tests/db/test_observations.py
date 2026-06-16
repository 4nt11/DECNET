# SPDX-License-Identifier: AGPL-3.0-or-later
"""ObservationRow model + repo tests — upsert idempotency,
latest-per-primitive query, time-series ordering.

Mirrors the test style of ``tests/db/test_credentials.py``: SQLite
``tmp_path`` factory, ``@pytest.mark.anyio`` markers, an ``Attacker``
seeded so observations have a valid FK target.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from decnet.web.db.factory import get_repository


def _envelope(
    *,
    primitive: str,
    value,
    attacker_uuid: str,
    evidence_ref: str,
    ts: float,
    confidence: float = 0.9,
    source: str = "decnet/profiler/behave_shell/extract.py",
    envelope_v: int = 1,
    identity_ref: str | None = None,
) -> dict:
    """Construct a minimal valid observation dict for upsert."""
    return {
        "id": uuid.uuid4().hex,
        "primitive": primitive,
        "value": value,
        "confidence": confidence,
        "window_start_ts": ts,
        "window_end_ts": ts,
        "source": source,
        "evidence_ref": evidence_ref,
        "envelope_v": envelope_v,
        "ts": ts,
        "identity_ref": identity_ref,
        "attacker_uuid": attacker_uuid,
    }


@pytest.fixture
async def repo(tmp_path: Path):
    r = get_repository(db_path=str(tmp_path / "observations.db"))
    await r.initialize()
    return r


@pytest.fixture
async def attacker_uuid(repo) -> str:
    """One Attacker row to FK observations against."""
    now = datetime.now(timezone.utc)
    return await repo.upsert_attacker({
        "ip": "10.0.0.7",
        "first_seen": now,
        "last_seen": now,
    })


@pytest.mark.anyio
async def test_upsert_then_read_back(repo, attacker_uuid: str) -> None:
    """Round-trip: every envelope field survives one insert + read."""
    payload = _envelope(
        primitive="motor.input_modality",
        value="pasted",
        attacker_uuid=attacker_uuid,
        evidence_ref="shard:decoy01/ssh/2026-05-03.jsonl#sid-A",
        ts=1714521660.456,
        confidence=0.91,
    )
    row_id = await repo.upsert_observation(payload)
    assert row_id == payload["id"]

    out = await repo.latest_observation_per_primitive(attacker_uuid)
    assert "motor.input_modality" in out
    assert out["motor.input_modality"]["value"] == "pasted"
    assert out["motor.input_modality"]["confidence"] == 0.91
    assert out["motor.input_modality"]["ts"] == 1714521660.456
    assert (
        out["motor.input_modality"]["source"]
        == "decnet/profiler/behave_shell/extract.py"
    )


@pytest.mark.anyio
async def test_upsert_idempotent_on_evidence_primitive(
    repo, attacker_uuid: str,
) -> None:
    """Same (evidence_ref, primitive) twice → one row, second wins on
    mutable fields, unique constraint not violated."""
    base = _envelope(
        primitive="motor.input_modality",
        value="typed",
        attacker_uuid=attacker_uuid,
        evidence_ref="shard:decoy01/ssh/2026-05-03.jsonl#sid-B",
        ts=1714521600.0,
        confidence=0.85,
    )
    first_id = await repo.upsert_observation(base)

    # Same key, different value + later ts. ``id`` field on the
    # incoming envelope should NOT replace the row's stored ``id``.
    rerun = {
        **base,
        "id": uuid.uuid4().hex,        # ignored on upsert path
        "value": "pasted",
        "ts": 1714521700.0,
        "confidence": 0.95,
    }
    second_id = await repo.upsert_observation(rerun)
    assert second_id == first_id, "natural-key upsert must not allocate a new row id"

    out = await repo.latest_observation_per_primitive(attacker_uuid)
    assert out["motor.input_modality"]["value"] == "pasted"
    assert out["motor.input_modality"]["ts"] == 1714521700.0
    assert out["motor.input_modality"]["confidence"] == 0.95


@pytest.mark.anyio
async def test_latest_per_primitive_returns_max_ts_only(
    repo, attacker_uuid: str,
) -> None:
    """Three observations of the same primitive at increasing ts —
    latest-per-primitive returns only the most recent.

    Distinct evidence_refs (one per session) so the unique constraint
    does NOT collapse them; this is the "drift over multiple sessions"
    case, not the "re-run extractor on same shard" case."""
    times = [1714000000.0, 1714000100.0, 1714000200.0]
    values = ["typed", "mixed", "pasted"]
    for ts, val in zip(times, values):
        await repo.upsert_observation(_envelope(
            primitive="motor.input_modality",
            value=val,
            attacker_uuid=attacker_uuid,
            evidence_ref=f"shard:decoy01/ssh/sid-{ts}",
            ts=ts,
        ))

    out = await repo.latest_observation_per_primitive(attacker_uuid)
    assert out["motor.input_modality"]["value"] == "pasted"
    assert out["motor.input_modality"]["ts"] == times[-1]


@pytest.mark.anyio
async def test_latest_per_primitive_does_not_interleave(
    repo, attacker_uuid: str,
) -> None:
    """Multiple primitives → one row each in the output; values stay
    matched to their primitive."""
    await repo.upsert_observation(_envelope(
        primitive="motor.input_modality",
        value="pasted",
        attacker_uuid=attacker_uuid,
        evidence_ref="shard:a#1",
        ts=1714000000.0,
    ))
    await repo.upsert_observation(_envelope(
        primitive="cognitive.feedback_loop_engagement",
        value="closed_loop",
        attacker_uuid=attacker_uuid,
        evidence_ref="shard:a#1",
        ts=1714000000.0,
    ))
    await repo.upsert_observation(_envelope(
        primitive="cognitive.command_branch_diversity",
        value="adaptive_branching",
        attacker_uuid=attacker_uuid,
        evidence_ref="shard:a#1",
        ts=1714000000.0,
    ))

    out = await repo.latest_observation_per_primitive(attacker_uuid)
    assert set(out.keys()) == {
        "motor.input_modality",
        "cognitive.feedback_loop_engagement",
        "cognitive.command_branch_diversity",
    }
    assert out["motor.input_modality"]["value"] == "pasted"
    assert out["cognitive.feedback_loop_engagement"]["value"] == "closed_loop"
    assert (
        out["cognitive.command_branch_diversity"]["value"]
        == "adaptive_branching"
    )


@pytest.mark.anyio
async def test_time_series_ordered_ascending(repo, attacker_uuid: str) -> None:
    """observations_time_series returns every row for one primitive,
    ordered by ``ts`` ASC."""
    times = [1714000300.0, 1714000100.0, 1714000200.0, 1714000000.0]
    for i, ts in enumerate(times):
        await repo.upsert_observation(_envelope(
            primitive="motor.paste_burst_rate",
            value="habitual",
            attacker_uuid=attacker_uuid,
            evidence_ref=f"shard:b#{i}",
            ts=ts,
            confidence=0.5 + 0.1 * i,
        ))

    series = await repo.observations_time_series(
        attacker_uuid, "motor.paste_burst_rate",
    )
    assert [row["ts"] for row in series] == sorted(times)
    assert all(row["value"] == "habitual" for row in series)


@pytest.mark.anyio
async def test_empty_attacker_returns_empty_dict(
    repo, attacker_uuid: str,
) -> None:
    """Attacker with no observations → empty dict, not 404."""
    out = await repo.latest_observation_per_primitive(attacker_uuid)
    assert out == {}


@pytest.mark.anyio
async def test_unknown_attacker_returns_empty_dict(repo) -> None:
    """Unseen attacker UUID → empty dict; the contract is "I have no
    observations" not "this attacker doesn't exist"."""
    out = await repo.latest_observation_per_primitive("00000000-0000-0000-0000-000000000000")
    assert out == {}


@pytest.mark.anyio
async def test_time_series_empty_when_primitive_absent(
    repo, attacker_uuid: str,
) -> None:
    """Time-series query for a primitive the attacker never emitted →
    empty list."""
    await repo.upsert_observation(_envelope(
        primitive="motor.input_modality",
        value="typed",
        attacker_uuid=attacker_uuid,
        evidence_ref="shard:c#1",
        ts=1714000000.0,
    ))
    series = await repo.observations_time_series(
        attacker_uuid, "cognitive.feedback_loop_engagement",
    )
    assert series == []


@pytest.mark.anyio
async def test_has_observations_for_evidence(
    repo, attacker_uuid: str,
) -> None:
    """The 'have we already profiled this session?' check: True iff
    any row carries the evidence_ref."""
    assert await repo.has_observations_for_evidence("shard:novel#1") is False

    await repo.upsert_observation(_envelope(
        primitive="motor.input_modality",
        value="pasted",
        attacker_uuid=attacker_uuid,
        evidence_ref="shard:novel#1",
        ts=1714000000.0,
    ))
    assert await repo.has_observations_for_evidence("shard:novel#1") is True
    # Multi-primitive write under the same evidence_ref: still True,
    # not duplicated.
    await repo.upsert_observation(_envelope(
        primitive="cognitive.feedback_loop_engagement",
        value="closed_loop",
        attacker_uuid=attacker_uuid,
        evidence_ref="shard:novel#1",
        ts=1714000000.0,
    ))
    assert await repo.has_observations_for_evidence("shard:novel#1") is True


@pytest.mark.anyio
async def test_value_roundtrip_preserves_jsonable_shapes(
    repo, attacker_uuid: str,
) -> None:
    """The ``value`` column is the union of every BEHAVE primitive's
    value kind. Round-trip a categorical string, a numeric, a hash
    string, a list, and a dict; all survive the JSON column."""
    cases = [
        ("motor.input_modality", "pasted"),
        ("toolchain.c2.beacon_interval_ms", 5000.0),
        ("toolchain.tls.jarm_server", "deadbeef" * 8),
        ("toolchain.ssh.kex_algorithm_order", ["curve25519", "ecdh-sha2"]),
        # Dict value — currently no SHELL primitive uses one but the
        # core envelope permits it; keep the contract live.
        ("future.dict_primitive", {"a": 1, "b": [2, 3]}),
    ]
    for i, (primitive, value) in enumerate(cases):
        await repo.upsert_observation(_envelope(
            primitive=primitive,
            value=value,
            attacker_uuid=attacker_uuid,
            evidence_ref=f"shard:roundtrip#{i}",
            ts=1714000000.0 + i,
        ))

    out = await repo.latest_observation_per_primitive(attacker_uuid)
    for primitive, value in cases:
        assert out[primitive]["value"] == value, primitive


@pytest.mark.anyio
async def test_idempotent_overwrite_does_not_violate_unique_constraint(
    repo, attacker_uuid: str,
) -> None:
    """Hammer the same key 5 times — single row, no IntegrityError."""
    for i in range(5):
        await repo.upsert_observation(_envelope(
            primitive="motor.input_modality",
            value="pasted",
            attacker_uuid=attacker_uuid,
            evidence_ref="shard:hammer#1",
            ts=1714000000.0 + i,
            confidence=0.5 + 0.05 * i,
        ))

    series = await repo.observations_time_series(
        attacker_uuid, "motor.input_modality",
    )
    assert len(series) == 1, "unique constraint must collapse re-runs"
    # Last write wins on mutable fields.
    assert series[0]["confidence"] == pytest.approx(0.7)
