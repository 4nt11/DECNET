"""Bus wiring for the collector (DEBT-031, worker 5).

Collector streams logs from Docker containers in a thread pool — can't be
exercised cleanly under pytest.  These tests pin the two things that
actually carry the contract:

1. ``_stream_container`` invokes ``publish_fn(parsed)`` right after writing
   the JSON record, and skips publish when the hook is absent.
2. ``_make_system_log_publisher`` routes under ``system.log`` with the
   expected compact payload shape.
"""
from __future__ import annotations

import asyncio
import json

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.collector.worker import (
    _make_system_log_publisher,
    _stream_container,
)


@pytest_asyncio.fixture
async def bus() -> FakeBus:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


# ─── Thread-safe publisher factory ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_publisher_routes_under_system_log(bus: FakeBus) -> None:
    loop = asyncio.get_running_loop()
    publish = _make_system_log_publisher(bus, loop)

    sub = bus.subscribe("system.log")
    async with sub:
        publish({
            "timestamp": "2026-04-21 10:00:00",
            "decky": "decky-a",
            "service": "ssh",
            "event_type": "auth_fail",
            "attacker_ip": "1.2.3.4",
        })
        event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)

    assert event.topic == "system.log"
    assert event.type == "auth_fail"
    assert event.payload == {
        "decky": "decky-a",
        "service": "ssh",
        "event_type": "auth_fail",
        "attacker_ip": "1.2.3.4",
        "timestamp": "2026-04-21 10:00:00",
    }


@pytest.mark.asyncio
async def test_publisher_no_bus_is_noop() -> None:
    # get_bus() failure path returns None → publisher is a no-op callable.
    loop = asyncio.get_running_loop()
    publish = _make_system_log_publisher(None, loop)
    # Must be safely invocable; no exception, no hang.
    publish({"event_type": "anything"})


# ─── Stream-thread integration: publish_fn wiring ────────────────────────────

class _FakeContainer:
    """Minimal duck-typed stand-in for docker.Container.logs(stream=True)."""

    def __init__(self, lines: list[bytes]) -> None:
        self._lines = lines

    def logs(self, stream=True, follow=True, stdout=True, stderr=False):
        yield from self._lines


class _FakeDockerClient:
    def __init__(self, container: _FakeContainer) -> None:
        self.containers = self  # so .get() lookup below works
        self._container = container

    def get(self, _container_id: str) -> _FakeContainer:
        return self._container


def _make_rfc5424_line() -> str:
    # Crafted to pass _RFC5424_RE in collector.worker.
    return (
        "<134>1 2026-04-21T10:00:00+00:00 decky-a ssh - auth_fail "
        "[decnet@32473 src_ip=\"1.2.3.4\"] failed password"
    )


def test_stream_container_invokes_publish_fn(monkeypatch, tmp_path):
    line = _make_rfc5424_line()
    fake_container = _FakeContainer([line.encode() + b"\n"])
    fake_client = _FakeDockerClient(fake_container)

    import docker as _docker_mod
    monkeypatch.setattr(_docker_mod, "from_env", lambda: fake_client)

    captured: list[dict] = []
    _stream_container(
        "cid-xyz",
        tmp_path / "decnet.log",
        tmp_path / "decnet.json",
        publish_fn=lambda parsed: captured.append(parsed),
    )

    # One parseable line → one publish call with the parsed dict.
    assert len(captured) == 1
    assert captured[0]["decky"] == "decky-a"
    assert captured[0]["service"] == "ssh"
    assert captured[0]["event_type"] == "auth_fail"

    # JSON file still written — bus publishing is additive, not a replacement.
    jf = (tmp_path / "decnet.json").read_text().strip().splitlines()
    assert len(jf) == 1
    assert json.loads(jf[0])["event_type"] == "auth_fail"


def test_stream_container_runs_without_publish_fn(monkeypatch, tmp_path):
    # Pre-bus behavior: no publish_fn, no crash, JSON still written.
    line = _make_rfc5424_line()
    fake_container = _FakeContainer([line.encode() + b"\n"])
    fake_client = _FakeDockerClient(fake_container)

    import docker as _docker_mod
    monkeypatch.setattr(_docker_mod, "from_env", lambda: fake_client)

    _stream_container(
        "cid-xyz",
        tmp_path / "decnet.log",
        tmp_path / "decnet.json",
    )

    jf = (tmp_path / "decnet.json").read_text().strip().splitlines()
    assert len(jf) == 1


def test_stream_container_swallows_publish_failures(monkeypatch, tmp_path):
    # Hook failure must not abort the stream thread.
    line = _make_rfc5424_line()
    fake_container = _FakeContainer([line.encode() + b"\n"])
    fake_client = _FakeDockerClient(fake_container)

    import docker as _docker_mod
    monkeypatch.setattr(_docker_mod, "from_env", lambda: fake_client)

    def _boom(_parsed):
        raise RuntimeError("transport exploded")

    # Must not raise.
    _stream_container(
        "cid-xyz",
        tmp_path / "decnet.log",
        tmp_path / "decnet.json",
        publish_fn=_boom,
    )

    jf = (tmp_path / "decnet.json").read_text().strip().splitlines()
    assert len(jf) == 1


# ─── Bus-disabled escape hatch ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collector_degrades_cleanly_when_bus_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from decnet.bus.factory import get_bus

    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")
    b = get_bus(client_name="collector")
    await b.connect()
    await b.publish("system.log", {"event_type": "auth_fail"}, event_type="auth_fail")
    await b.close()
