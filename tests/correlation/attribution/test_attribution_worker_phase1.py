# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 1 attribution worker — wiring smoke tests.

The Phase 1 worker subscribes to ``attacker.observation.>`` and, for
each event, ensures the source attacker has a stub identity row.
That's it — no merger, no state writes, no derived events. These
tests pin the wiring + the stub-materialisation contract.

Phase 4 will extend with end-to-end state-row + transition-event
assertions.
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
    r = get_repository(db_path=str(tmp_path / "attribution_wiring.db"))
    await r.initialize()
    return r


@pytest.fixture
async def attacker_uuid(repo) -> str:
    now = datetime.now(timezone.utc)
    return await repo.upsert_attacker({
        "ip": "10.0.0.42",
        "first_seen": now,
        "last_seen": now,
    })


def _make_event(payload: dict[str, Any]) -> Any:
    """Light Event-shaped object — the handler reads ``.payload``
    via ``getattr`` and falls back to dicts. We pass a dict directly
    because that's what tests give the BEHAVE handler too."""
    return payload


@pytest.mark.anyio
async def test_handle_event_creates_stub_for_known_attacker(
    repo, attacker_uuid: str,
) -> None:
    """First observation for an attacker → stub identity created and
    stamped onto the Attacker row."""
    bus = FakeBus()
    await bus.connect()
    payload = {
        "attacker_uuid": attacker_uuid,
        "primitive": "motor.input_modality",
        "value": "pasted",
        "ts": 1714000000.0,
        "confidence": 0.9,
    }
    await _aw.handle_observation_event(bus, repo, _make_event(payload))

    attacker = await repo.get_attacker_by_uuid(attacker_uuid)
    assert attacker is not None
    assert attacker["identity_id"] is not None

    # Second event re-uses the same stub.
    await _aw.handle_observation_event(bus, repo, _make_event(payload))
    attacker_again = await repo.get_attacker_by_uuid(attacker_uuid)
    assert attacker_again["identity_id"] == attacker["identity_id"]
    await bus.close()


@pytest.mark.anyio
async def test_handle_event_defers_for_missing_attacker(repo) -> None:
    """No Attacker row yet → handler returns without raising and
    without inserting an orphan identity (the worker treats this as
    'profiler hasn't materialised the attacker, defer')."""
    bus = FakeBus()
    await bus.connect()
    payload = {
        "attacker_uuid": "00000000000000000000000000000000",
        "primitive": "motor.input_modality",
        "value": "pasted",
        "ts": 1714000000.0,
        "confidence": 0.9,
    }
    # Should NOT raise.
    await _aw.handle_observation_event(bus, repo, _make_event(payload))
    # No identities materialised.
    identities = await repo.list_all_identities()
    assert identities == []
    await bus.close()


@pytest.mark.anyio
async def test_handle_event_skips_malformed_payload(
    repo, attacker_uuid: str,
) -> None:
    """Missing attacker_uuid or primitive → log + continue, never
    raise. Bus delivery is at-least-once; bad payloads must not
    poison the consumer."""
    bus = FakeBus()
    await bus.connect()
    for bad in (
        {"primitive": "motor.input_modality"},   # missing attacker_uuid
        {"attacker_uuid": attacker_uuid},        # missing primitive
        {},                                      # both missing
    ):
        await _aw.handle_observation_event(bus, repo, _make_event(bad))

    # No identity materialised because every payload was rejected
    # before the stub helper ran.
    attacker = await repo.get_attacker_by_uuid(attacker_uuid)
    assert attacker is not None
    assert attacker["identity_id"] is None
    await bus.close()


@pytest.mark.anyio
async def test_handle_event_idempotent_per_observation(
    repo, attacker_uuid: str,
) -> None:
    """Hammer the same payload N times — one stub identity, no
    duplicate rows, no exception."""
    bus = FakeBus()
    await bus.connect()
    payload = {
        "attacker_uuid": attacker_uuid,
        "primitive": "motor.input_modality",
        "value": "pasted",
        "ts": 1714000000.0,
        "confidence": 0.9,
    }
    for _ in range(5):
        await _aw.handle_observation_event(bus, repo, _make_event(payload))

    identities = await repo.list_all_identities()
    assert len(identities) == 1
    await bus.close()


@pytest.mark.anyio
async def test_event_object_payload_attribute(
    repo, attacker_uuid: str,
) -> None:
    """Real bus events carry payload on ``.payload``; the handler
    must follow the attribute, not assume the event itself is the
    dict."""
    class _Evt:
        def __init__(self, payload: dict[str, Any]) -> None:
            self.payload = payload

    bus = FakeBus()
    await bus.connect()
    payload = {
        "attacker_uuid": attacker_uuid,
        "primitive": "cognitive.feedback_loop_engagement",
        "value": "closed_loop",
        "ts": 1714000000.0,
        "confidence": 0.85,
    }
    await _aw.handle_observation_event(bus, repo, _Evt(payload))
    attacker = await repo.get_attacker_by_uuid(attacker_uuid)
    assert attacker is not None
    assert attacker["identity_id"] is not None
    await bus.close()
