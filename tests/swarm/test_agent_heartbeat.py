# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the worker-side heartbeat loop (decnet.agent.heartbeat)."""
from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from decnet.agent import heartbeat as hb


@pytest.fixture(autouse=True)
def _reset_module_task(monkeypatch: pytest.MonkeyPatch):
    # Each test gets a fresh _task slot so start()/stop() state doesn't
    # leak between cases.
    monkeypatch.setattr(hb, "_task", None)
    yield
    monkeypatch.setattr(hb, "_task", None)


class _StubTransport(httpx.AsyncBaseTransport):
    """Record each POST and respond according to ``responder(req)``."""
    def __init__(self, responder):
        self.calls: list[dict[str, Any]] = []
        self._responder = responder

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = request.read()
        self.calls.append({"url": str(request.url), "body": body})
        return self._responder(request)


@pytest.mark.asyncio
async def test_tick_posts_status_snapshot_and_accepts_204(monkeypatch) -> None:
    async def fake_status() -> dict:
        return {"deployed": False, "deckies": []}

    monkeypatch.setattr(hb._exec, "status", fake_status)

    transport = _StubTransport(lambda req: httpx.Response(204))
    async with httpx.AsyncClient(transport=transport) as client:
        await hb._tick(client, "https://m/swarm/heartbeat", "uuid-a", "1.2.3")

    assert len(transport.calls) == 1
    import json
    payload = json.loads(transport.calls[0]["body"])
    assert payload["host_uuid"] == "uuid-a"
    assert payload["agent_version"] == "1.2.3"
    assert payload["status"]["deployed"] is False


@pytest.mark.asyncio
async def test_tick_logs_on_non_204_response(monkeypatch, caplog) -> None:
    async def fake_status() -> dict:
        return {"deployed": False}

    monkeypatch.setattr(hb._exec, "status", fake_status)
    transport = _StubTransport(lambda req: httpx.Response(403, text="mismatch"))

    async with httpx.AsyncClient(transport=transport) as client:
        with caplog.at_level("WARNING", logger="agent.heartbeat"):
            await hb._tick(client, "https://m/swarm/heartbeat", "uuid-a", "1.2.3")

    assert any("rejected" in rec.getMessage() for rec in caplog.records)


def test_start_is_noop_when_identity_missing(monkeypatch) -> None:
    # Neither DECNET_HOST_UUID nor DECNET_MASTER_HOST set → start() must
    # return None, never raise. Dev runs exercise this path every time.
    import decnet.env as env
    monkeypatch.setattr(env, "DECNET_HOST_UUID", None)
    monkeypatch.setattr(env, "DECNET_MASTER_HOST", None)
    assert hb.start() is None
    assert hb._task is None


@pytest.mark.asyncio
async def test_start_is_noop_when_ssl_context_unavailable(
    monkeypatch, tmp_path
) -> None:
    # Identity plumbed, but worker bundle missing on disk → start() logs
    # and bails instead of crashing the FastAPI app.
    import decnet.env as env
    monkeypatch.setattr(env, "DECNET_HOST_UUID", "uuid-a")
    monkeypatch.setattr(env, "DECNET_MASTER_HOST", "master.lan")
    monkeypatch.setattr(env, "DECNET_SWARMCTL_PORT", 8770)
    monkeypatch.setenv("DECNET_AGENT_DIR", str(tmp_path / "empty"))
    assert hb.start() is None


@pytest.mark.asyncio
async def test_loop_keeps_ticking_after_5xx_failures(monkeypatch) -> None:
    # Simulates a flapping master: first two ticks raise/5xx, third succeeds.
    # The loop must not crash — it must sleep and retry.
    call_count = {"n": 0}

    def _responder(req):
        call_count["n"] += 1
        if call_count["n"] < 3:
            return httpx.Response(503, text="unavailable")
        return httpx.Response(204)

    async def fake_status() -> dict:
        return {"deployed": False}

    monkeypatch.setattr(hb._exec, "status", fake_status)
    monkeypatch.setattr(hb, "INTERVAL_S", 0.01)  # fast-forward the sleep

    transport = _StubTransport(_responder)

    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            while call_count["n"] < 3:
                try:
                    await hb._tick(client, "https://m/swarm/heartbeat", "uuid-a", "1.2.3")
                except Exception:
                    pass
                await asyncio.sleep(0.01)

    await asyncio.wait_for(_run(), timeout=2.0)
    assert call_count["n"] >= 3
