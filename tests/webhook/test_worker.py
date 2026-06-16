# SPDX-License-Identifier: AGPL-3.0-or-later
"""Webhook worker — bus consumer → HTTP egress integration test."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from decnet.bus import topics as _topics
from decnet.webhook.worker import (
    _patterns_for,
    _union_patterns,
    webhook_worker,
)


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch: pytest.MonkeyPatch):
    """Resolve the test webhook host to a public IP so the egress SSRF guard
    passes for these integration tests without touching the network."""
    import socket

    from decnet.webhook import ssrf

    def fake_getaddrinfo(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake_getaddrinfo)


def _sub(
    uuid: str,
    name: str,
    patterns: list[str],
    *,
    url: str = "https://w.example/x",
    secret: str = "s" * 32,
    enabled: bool = True,
) -> dict[str, Any]:
    return {
        "uuid": uuid,
        "name": name,
        "url": url,
        "secret": secret,
        "topic_patterns": json.dumps(patterns),
        "enabled": enabled,
        "consecutive_failures": 0,
        "last_success_at": None,
        "last_failure_at": None,
        "last_error": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }


class _FakeRepo:
    def __init__(self, subs: list[dict[str, Any]]):
        self.subs = subs
        self.success_calls: list[str] = []
        self.failure_calls: list[tuple[str, str]] = []
        self.trip_calls: list[str] = []
        self._failure_counts: dict[str, int] = {}

    async def list_webhook_subscriptions(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        return [s for s in self.subs if s["enabled"]] if enabled_only else list(self.subs)

    async def record_webhook_success(self, uuid: str, ts: datetime) -> None:
        self.success_calls.append(uuid)
        self._failure_counts[uuid] = 0

    async def record_webhook_failure(self, uuid: str, ts: datetime, error: str) -> int:
        self.failure_calls.append((uuid, error))
        self._failure_counts[uuid] = self._failure_counts.get(uuid, 0) + 1
        return self._failure_counts[uuid]

    async def trip_webhook_circuit(self, uuid: str, ts: datetime) -> None:
        self.trip_calls.append(uuid)
        # Mirror the real DB effect: flip enabled=False so next reload
        # skips this sub.
        for s in self.subs:
            if s["uuid"] == uuid:
                s["enabled"] = False
                s["auto_disabled_at"] = ts


def test_patterns_for_decodes_json():
    assert _patterns_for(
        {"topic_patterns": json.dumps(["attacker.>", "decky.*.state"])}
    ) == ["attacker.>", "decky.*.state"]


def test_patterns_for_bad_json_returns_empty():
    assert _patterns_for({"topic_patterns": "not-json"}) == []


def test_union_patterns_dedupes_across_subs():
    s1 = _sub("u1", "w1", ["attacker.>", "system.>"])
    s2 = _sub("u2", "w2", ["system.>", "decky.*.state"])
    assert _union_patterns([s1, s2]) == ["attacker.>", "system.>", "decky.*.state"]


@pytest.mark.asyncio
async def test_worker_dispatches_matching_event(fake_bus):
    """A bus event matching a sub's pattern should produce an HTTP POST."""
    sub = _sub("u1", "w1", ["attacker.>"])
    repo = _FakeRepo([sub])
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with patch("decnet.webhook.worker.get_bus", return_value=fake_bus):
            task = asyncio.create_task(
                webhook_worker(repo, reload_interval=0.5, http_client=client)
            )
            # Give the worker a moment to subscribe.
            await asyncio.sleep(0.2)

            await fake_bus.publish(
                "attacker.observed",
                {"ip": "1.2.3.4"},
                event_type="first_sighting",
            )
            # Poll briefly for delivery.
            for _ in range(40):
                if captured:
                    break
                await asyncio.sleep(0.05)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    assert len(captured) == 1
    req = captured[0]
    assert req.headers.get("X-DECNET-Signature", "").startswith("sha256=")
    assert "attacker.observed" in req.headers.get("X-DECNET-Event-Topic", "")
    assert repo.success_calls == ["u1"]


@pytest.mark.asyncio
async def test_worker_ignores_non_matching_event(fake_bus):
    """An event outside the sub's pattern must not trigger a POST."""
    sub = _sub("u1", "w1", ["attacker.>"])
    repo = _FakeRepo([sub])
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with patch("decnet.webhook.worker.get_bus", return_value=fake_bus):
            task = asyncio.create_task(
                webhook_worker(repo, reload_interval=0.5, http_client=client)
            )
            await asyncio.sleep(0.2)
            # system.log is NOT in attacker.>
            await fake_bus.publish(
                "system.log",
                {"m": "irrelevant"},
                event_type="batch_committed",
            )
            await asyncio.sleep(0.3)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    assert captured == []
    assert repo.success_calls == []


@pytest.mark.asyncio
async def test_worker_records_failure_on_5xx(fake_bus, monkeypatch):
    sub = _sub("u1", "w1", ["attacker.>"])
    repo = _FakeRepo([sub])

    # Collapse the retry schedule to zero-delay so the test doesn't wait
    # the real 1+2+4s backoff sequence.
    monkeypatch.setattr(
        "decnet.webhook.client._DEFAULT_RETRY_SCHEDULE", (0.0, 0.0, 0.0)
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with patch("decnet.webhook.worker.get_bus", return_value=fake_bus):
            task = asyncio.create_task(
                webhook_worker(repo, reload_interval=0.5, http_client=client)
            )
            await asyncio.sleep(0.2)
            await fake_bus.publish(
                "attacker.observed", {"ip": "1.2.3.4"}, event_type="x"
            )
            for _ in range(80):
                if repo.failure_calls:
                    break
                await asyncio.sleep(0.05)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    assert repo.failure_calls
    assert repo.failure_calls[0][0] == "u1"


@pytest.mark.asyncio
async def test_worker_reloads_on_subscriptions_changed_signal(fake_bus):
    """A newly-enabled sub that arrives via the reload-signal path must
    start receiving events without a worker restart."""
    subs = [_sub("u1", "w1", ["attacker.>"])]
    repo = _FakeRepo(subs)
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with patch("decnet.webhook.worker.get_bus", return_value=fake_bus):
            task = asyncio.create_task(
                webhook_worker(repo, reload_interval=60.0, http_client=client)
            )
            await asyncio.sleep(0.2)

            # Hot-add a sub that wants system.>
            subs.append(_sub("u2", "w2", ["system.>"]))
            await fake_bus.publish(
                _topics.WEBHOOK_SUBSCRIPTIONS_CHANGED, {}, event_type="changed"
            )
            await asyncio.sleep(0.3)  # let worker reload + resubscribe

            await fake_bus.publish(
                "system.log", {"m": "hi"}, event_type="batch_committed"
            )
            for _ in range(80):
                if captured:
                    break
                await asyncio.sleep(0.05)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


    # The new sub (u2) should have received the system.log event.
    assert len(captured) == 1
    assert "system.log" in captured[0].headers.get("X-DECNET-Event-Topic", "")


@pytest.mark.asyncio
async def test_worker_trips_circuit_after_threshold(fake_bus, monkeypatch):
    """After N consecutive failures the worker auto-disables the sub."""
    sub = _sub("u1", "w1", ["attacker.>"])
    repo = _FakeRepo([sub])

    # Tight threshold + zero-delay retry so the test finishes fast.
    monkeypatch.setattr("decnet.webhook.worker._CIRCUIT_THRESHOLD", 2)
    monkeypatch.setattr(
        "decnet.webhook.client._DEFAULT_RETRY_SCHEDULE", (0.0, 0.0, 0.0)
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with patch("decnet.webhook.worker.get_bus", return_value=fake_bus):
            task = asyncio.create_task(
                webhook_worker(repo, reload_interval=0.5, http_client=client)
            )
            await asyncio.sleep(0.2)
            # Publish two events — each fails N retries, each increments
            # consecutive_failures by 1. Second trip should fire.
            await fake_bus.publish("attacker.observed", {}, event_type="x")
            await fake_bus.publish("attacker.observed", {}, event_type="x")
            for _ in range(120):
                if repo.trip_calls:
                    break
                await asyncio.sleep(0.05)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    assert repo.trip_calls, "expected circuit to trip after threshold"
    assert repo.trip_calls[0] == "u1"
    # The sub was flipped to enabled=False by trip_webhook_circuit.
    assert sub["enabled"] is False
    assert sub["auto_disabled_at"] is not None


@pytest.mark.asyncio
async def test_worker_self_heals_when_bus_starts_late(fake_bus):
    """Bus down at startup → worker parks in a retry loop. Once the bus
    comes up on the next attempt, the worker transitions to dispatch
    mode and delivers events normally.
    """
    sub = _sub("u1", "w1", ["attacker.>"])
    repo = _FakeRepo([sub])
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    # First call: raise (bus unavailable). Second call: hand out the
    # FakeBus. The worker's retry loop should bridge the gap.
    calls = {"n": 0}

    def flaky_get_bus(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("bus not ready yet")
        return fake_bus

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with patch("decnet.webhook.worker.get_bus", side_effect=flaky_get_bus):
            task = asyncio.create_task(
                webhook_worker(
                    repo,
                    reload_interval=0.5,
                    http_client=client,
                    bus_reconnect_secs=0.3,
                )
            )
            # First attempt fails, worker waits bus_reconnect_secs, second
            # attempt succeeds. Give it a generous window.
            await asyncio.sleep(0.8)

            await fake_bus.publish(
                "attacker.observed", {"ip": "1.2.3.4"}, event_type="x"
            )
            for _ in range(60):
                if captured:
                    break
                await asyncio.sleep(0.05)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    assert calls["n"] >= 2, "expected at least one retry after initial failure"
    assert len(captured) == 1, "expected delivery once bus came up"

