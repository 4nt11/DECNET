# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSE events stream — GET /attackers/{uuid}/events (Phase 5).

Mirrors the topology events test pattern at
``tests/api/topology/test_events_stream.py`` — drives the generator
directly to avoid the full httpx streaming roundtrip, which is
painful under ASGITransport + an infinite SSE loop.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from decnet.bus import app as _bus_app
from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.web.api import app
from decnet.web.dependencies import repo as _repo

_V1 = "/api/v1/attackers"
_OTHER_UUID = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def _fake_app_bus(monkeypatch):
    bus = FakeBus()

    async def _get() -> FakeBus:
        if not bus._connected:
            await bus.connect()
        return bus

    monkeypatch.setattr(_bus_app, "get_app_bus", _get)
    from decnet.web.router.attackers import api_events as _ev
    monkeypatch.setattr(_ev, "get_app_bus", _get)
    return bus


async def _seed_attacker(ip: str = "10.0.0.5") -> str:
    """Persist a minimal Attacker row, return its uuid."""
    return await _repo.upsert_attacker({
        "ip": ip,
        "first_seen": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
        "event_count": 1,
        "service_count": 1,
        "decky_count": 1,
        "services": "[\"ssh\"]",
        "deckies": "[\"d1\"]",
        "traversal_path": None,
        "is_traversal": False,
        "bounty_count": 0,
        "credential_count": 0,
        "fingerprints": "[]",
        "commands": "[]",
        "country_code": None,
        "country_source": None,
        "asn": None,
        "as_name": None,
        "asn_source": None,
        "updated_at": datetime.now(timezone.utc),
    })


async def _seed_observation(
    attacker_uuid: str,
    primitive: str,
    value: str,
    confidence: float = 0.85,
) -> None:
    await _repo.upsert_observation({
        "primitive": primitive,
        "value": value,
        "confidence": confidence,
        "window_start_ts": 0.0,
        "window_end_ts": 1.0,
        "source": "test",
        "evidence_ref": f"shard:test#{primitive}",
        "envelope_v": 1,
        "ts": 1714521660.456,
        "attacker_uuid": attacker_uuid,
    })


# ── Auth / 404 paths ────────────────────────────────────────────────


@pytest.mark.anyio
async def test_events_unauthenticated_401(_fake_app_bus):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    ) as ac:
        r = await ac.get(f"{_V1}/any-uuid/events")
        assert r.status_code == 401


@pytest.mark.anyio
async def test_events_missing_attacker_404(auth_token, _fake_app_bus):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    ) as ac:
        # SSE auth is a single-use ?ticket= minted from the JWT (EventSource
        # can't set headers); a raw ?token= is no longer accepted.
        tr = await ac.post(
            "/api/v1/auth/sse-ticket",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert tr.status_code == 200, tr.text
        ticket = tr.json()["ticket"]
        r = await ac.get(
            f"{_V1}/{_OTHER_UUID}/events",
            params={"ticket": ticket},
        )
        assert r.status_code == 404


# ── Generator-driven tests ──────────────────────────────────────────


def _as_text(frame) -> str:
    return frame if isinstance(frame, str) else frame.decode()


async def _drive_until(gen, predicate, *, max_frames: int = 8) -> tuple[bool, list[str]]:
    """Pump frames out of the generator until ``predicate(frame)`` is
    True or ``max_frames`` is exhausted. Returns ``(matched, frames_seen)``."""
    seen: list[str] = []
    for _ in range(max_frames):
        frame = _as_text(await gen.__anext__())
        seen.append(frame)
        if predicate(frame):
            return True, seen
    return False, seen


@pytest.mark.anyio
async def test_emits_snapshot_on_connect(auth_token, _fake_app_bus):
    """Snapshot frame fires immediately and contains seeded observations."""
    attacker_uuid = await _seed_attacker(ip="10.0.0.5")
    await _seed_observation(attacker_uuid, "motor.input_modality", "typed")

    from decnet.web.router.attackers import api_events as _ev

    class _FakeRequest:
        async def is_disconnected(self) -> bool:
            return False

    response = await _ev.api_attacker_events(
        attacker_uuid=attacker_uuid,
        request=_FakeRequest(),  # type: ignore[arg-type]
        user={"role": "admin", "uuid": "00000000-0000-0000-0000-000000000000"},
    )
    gen = response.body_iterator
    try:
        matched, seen = await asyncio.wait_for(
            _drive_until(
                gen,
                lambda f: "event: snapshot" in f and "motor.input_modality" in f,
            ),
            timeout=5.0,
        )
    finally:
        await gen.aclose()
    assert matched, f"snapshot not found in frames: {seen}"


@pytest.mark.anyio
async def test_forwards_observation_for_this_attacker(auth_token, _fake_app_bus):
    """A live attacker.observation event reaches the SSE stream."""
    attacker_uuid = await _seed_attacker(ip="10.0.0.6")

    from decnet.web.router.attackers import api_events as _ev

    class _FakeRequest:
        async def is_disconnected(self) -> bool:
            return False

    response = await _ev.api_attacker_events(
        attacker_uuid=attacker_uuid,
        request=_FakeRequest(),  # type: ignore[arg-type]
        user={"role": "admin", "uuid": "00000000-0000-0000-0000-000000000000"},
    )
    gen = response.body_iterator

    async def _publish_after_snapshot() -> None:
        await asyncio.sleep(0.1)
        await _fake_app_bus.publish(
            _topics.attacker_observation("motor.input_modality"),
            {"attacker_uuid": attacker_uuid, "primitive": "motor.input_modality",
             "value": "pasted", "confidence": 0.9},
            event_type="motor.input_modality",
        )

    pub_task = asyncio.create_task(_publish_after_snapshot())
    try:
        matched, seen = await asyncio.wait_for(
            _drive_until(
                gen,
                # Event name is "observation"; primitive rides in payload.
                lambda f: "event: observation" in f
                and "motor.input_modality" in f,
            ),
            timeout=5.0,
        )
    finally:
        pub_task.cancel()
        try:
            await pub_task
        except (asyncio.CancelledError, Exception):
            pass
        await gen.aclose()
    assert matched, f"live frame not found: {seen}"


@pytest.mark.anyio
async def test_drops_observation_for_other_attackers(auth_token, _fake_app_bus):
    """An event with a different attacker_uuid must NOT be forwarded.

    We can't wait forever for a nothing — so we publish ONE matching
    event first, drive past it, then publish a non-matching event,
    then publish another matching event, and assert the
    middle-non-matching frame never appeared between the two matches.
    """
    attacker_uuid = await _seed_attacker(ip="10.0.0.7")

    from decnet.web.router.attackers import api_events as _ev

    class _FakeRequest:
        async def is_disconnected(self) -> bool:
            return False

    response = await _ev.api_attacker_events(
        attacker_uuid=attacker_uuid,
        request=_FakeRequest(),  # type: ignore[arg-type]
        user={"role": "admin", "uuid": "00000000-0000-0000-0000-000000000000"},
    )
    gen = response.body_iterator

    async def _publish_sequence() -> None:
        await asyncio.sleep(0.1)
        # Non-matching event — must be dropped by the per-attacker filter.
        await _fake_app_bus.publish(
            _topics.attacker_observation("motor.input_modality"),
            {"attacker_uuid": _OTHER_UUID, "primitive": "motor.input_modality",
             "value": "should-not-appear"},
            event_type="motor.input_modality",
        )
        await asyncio.sleep(0.05)
        # Matching event — drives the loop forward, so we know the
        # non-matching one had its chance.
        await _fake_app_bus.publish(
            _topics.attacker_observation("cognitive.cognitive_load"),
            {"attacker_uuid": attacker_uuid, "primitive": "cognitive.cognitive_load",
             "value": "high"},
            event_type="cognitive.cognitive_load",
        )

    pub_task = asyncio.create_task(_publish_sequence())
    try:
        matched, seen = await asyncio.wait_for(
            _drive_until(
                gen,
                lambda f: "event: observation" in f
                and "cognitive.cognitive_load" in f,
            ),
            timeout=5.0,
        )
    finally:
        pub_task.cancel()
        try:
            await pub_task
        except (asyncio.CancelledError, Exception):
            pass
        await gen.aclose()
    assert matched, f"matching frame missing: {seen}"
    # The dropped event's distinguishing string must never appear.
    assert not any("should-not-appear" in f for f in seen), (
        f"per-attacker filter leaked: {seen}"
    )


@pytest.mark.anyio
async def test_includes_fingerprint_rotated_for_this_attacker(
    auth_token, _fake_app_bus,
):
    attacker_uuid = await _seed_attacker(ip="10.0.0.8")

    from decnet.web.router.attackers import api_events as _ev

    class _FakeRequest:
        async def is_disconnected(self) -> bool:
            return False

    response = await _ev.api_attacker_events(
        attacker_uuid=attacker_uuid,
        request=_FakeRequest(),  # type: ignore[arg-type]
        user={"role": "admin", "uuid": "00000000-0000-0000-0000-000000000000"},
    )
    gen = response.body_iterator

    async def _publish() -> None:
        await asyncio.sleep(0.1)
        await _fake_app_bus.publish(
            _topics.attacker(_topics.ATTACKER_FINGERPRINT_ROTATED),
            {"attacker_uuid": attacker_uuid, "old_fp": "a", "new_fp": "b"},
            event_type=_topics.ATTACKER_FINGERPRINT_ROTATED,
        )

    pub_task = asyncio.create_task(_publish())
    try:
        matched, seen = await asyncio.wait_for(
            _drive_until(gen, lambda f: "event: fingerprint.rotated" in f),
            timeout=5.0,
        )
    finally:
        pub_task.cancel()
        try:
            await pub_task
        except (asyncio.CancelledError, Exception):
            pass
        await gen.aclose()
    assert matched


# ── _sse_name_for unit ──────────────────────────────────────────────


def test_sse_name_for_observation_collapses_to_single_event_name():
    """Per-primitive events all share the SSE event name 'observation';
    the primitive rides in payload."""
    from decnet.web.router.attackers.api_events import _sse_name_for
    assert (
        _sse_name_for("attacker.observation.motor.input_modality")
        == "observation"
    )
    assert (
        _sse_name_for("attacker.observation.motor.shell_mastery.tab_completion")
        == "observation"
    )


def test_sse_name_for_fingerprint_rotated():
    from decnet.web.router.attackers.api_events import _sse_name_for
    assert _sse_name_for("attacker.fingerprint_rotated") == "fingerprint.rotated"


def test_sse_name_for_scored():
    from decnet.web.router.attackers.api_events import _sse_name_for
    assert _sse_name_for("attacker.scored") == "attacker.scored"


def test_sse_name_for_unknown_passes_through():
    from decnet.web.router.attackers.api_events import _sse_name_for
    assert _sse_name_for("attacker.something_new") == "attacker.something_new"
