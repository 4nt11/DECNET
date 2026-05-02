"""Reuse correlator publishes ``credential.reuse.detected``.

Pins the producer wiring so a regression that silently drops the
publish (e.g. someone moves the loop body or mis-spells the topic
constant) trips this test on the next run.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.correlation import reuse_worker as _rw


@pytest.mark.asyncio
async def test_reuse_correlator_publishes_on_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = FakeBus()
    await bus.connect()

    async def _fake_get_bus(*_a: Any, **_kw: Any) -> FakeBus:
        return bus

    # Worker calls `get_bus(...)` synchronously; replace with a sync
    # callable returning the live fake. `connect()` on the fake is a
    # no-op, so calling it again from inside the worker is harmless.
    monkeypatch.setattr(
        _rw, "get_bus", lambda *_a, **_kw: bus,
    )

    captured: list[tuple[str, dict[str, Any]]] = []
    sub = bus.subscribe(
        _topics.credential(_topics.CREDENTIAL_REUSE_DETECTED),
    )

    async def drain() -> None:
        try:
            async with sub:
                async for ev in sub:
                    captured.append((ev.topic, ev.payload))
        except Exception:
            pass

    drain_task = asyncio.create_task(drain())
    await asyncio.sleep(0)

    # Stub the engine's correlate to return a single reuse row on the
    # first tick.  Subsequent ticks return [] so the publish doesn't
    # spam.
    seen_ticks: list[int] = []
    finding = {
        "id": "reuse-1",
        "secret_kind": "password",
        "target_count": 3,
        "attacker_uuids": ["att-1", "att-2"],
        "attacker_ips": ["1.2.3.4", "5.6.7.8"],
        "deckies": ["decky-a", "decky-b"],
        "services": ["ssh", "ftp"],
    }

    async def _fake_correlate(
        _self: Any, _repo: Any, *, min_targets: int = 2,
    ) -> list[dict[str, Any]]:
        seen_ticks.append(0)
        return [finding] if len(seen_ticks) == 1 else []

    monkeypatch.setattr(
        _rw.CorrelationEngine, "correlate_credential_reuse", _fake_correlate,
    )

    shutdown = asyncio.Event()

    class _RepoStub:
        async def get_state(self, _key: str) -> None:
            return None

        async def set_state(self, _key: str, _val: dict[str, Any]) -> None:
            return None

    loop_task = asyncio.create_task(_rw.run_reuse_loop(
        _RepoStub(),  # type: ignore[arg-type]
        poll_interval_secs=0.05, shutdown=shutdown,
    ))
    # One tick is enough — the stub returns the finding immediately,
    # publishes, then the next tick yields []. Settle, then stop.
    await asyncio.sleep(0.15)
    shutdown.set()
    await asyncio.wait_for(loop_task, timeout=2.0)
    drain_task.cancel()
    await bus.close()

    assert len(captured) >= 1
    topic, payload = captured[0]
    assert topic == _topics.credential(_topics.CREDENTIAL_REUSE_DETECTED)
    assert payload["id"] == "reuse-1"
    assert payload["target_count"] == 3
    assert payload["secret_kind"] == "password"
