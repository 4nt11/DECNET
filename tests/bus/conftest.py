"""Shared fixtures for decnet.bus tests."""
from __future__ import annotations

import asyncio
import pathlib
from typing import AsyncIterator

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.bus.unix_client import UnixSocketBus
from decnet.bus.unix_server import BusServer


@pytest_asyncio.fixture
async def fake_bus() -> AsyncIterator[FakeBus]:
    bus = FakeBus()
    await bus.connect()
    try:
        yield bus
    finally:
        await bus.close()


@pytest_asyncio.fixture
async def unix_bus(tmp_path: pathlib.Path) -> AsyncIterator[tuple[BusServer, UnixSocketBus]]:
    """Spin a BusServer on a tmp socket, yield (server, connected client).

    Teardown closes both in the right order.  No privileged group chown —
    the fixture passes ``group=None`` so the socket stays owned by the
    test-runner's process group.
    """
    sock = tmp_path / "bus.sock"
    server = BusServer(sock, group=None)
    await server.start()
    serve_task = asyncio.create_task(server.serve_forever())

    client = UnixSocketBus(sock, client_name="test-client")
    await client.connect()

    try:
        yield server, client
    finally:
        await client.close()
        serve_task.cancel()
        try:
            await serve_task
        except asyncio.CancelledError:
            pass
        await server.close()


@pytest.fixture
def bus_env_fake(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point :func:`decnet.bus.factory.get_bus` at the in-process FakeBus."""
    monkeypatch.setenv("DECNET_BUS_TYPE", "fake")
    monkeypatch.setenv("DECNET_BUS_ENABLED", "true")
    monkeypatch.delenv("DECNET_BUS_SOCKET", raising=False)
