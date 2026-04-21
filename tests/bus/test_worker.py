"""Tests for :func:`decnet.bus.worker.bus_worker` lifecycle + heartbeat."""
from __future__ import annotations

import asyncio
import pathlib

import pytest

from decnet.bus import topics
from decnet.bus.unix_client import UnixSocketBus
from decnet.bus.worker import bus_worker


class TestBusWorker:
    async def test_worker_serves_and_heartbeats(
        self, tmp_path: pathlib.Path,
    ) -> None:
        sock = tmp_path / "bus.sock"
        task = asyncio.create_task(
            bus_worker(sock, group=None, heartbeat_interval=1),
        )
        # Wait for the socket to exist.
        for _ in range(40):
            if sock.exists():
                break
            await asyncio.sleep(0.05)
        assert sock.exists(), "bus worker did not create socket"

        client = UnixSocketBus(sock, client_name="hb-watcher")
        await client.connect()
        sub = client.subscribe(topics.system(topics.SYSTEM_BUS_HEALTH))
        try:
            async with sub:
                async with asyncio.timeout(3.0):
                    async for event in sub:
                        assert event.topic == "system.bus.health"
                        assert "pid" in event.payload
                        break
        finally:
            await client.close()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def test_worker_creates_home_fallback_parent(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Point Path.home() at tmp_path so the "auto-mkdir ~/.decnet" branch
        # activates without touching the real home directory.
        monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
        sock = tmp_path / ".decnet" / "bus.sock"
        task = asyncio.create_task(
            bus_worker(sock, group=None, heartbeat_interval=60),
        )
        try:
            for _ in range(40):
                if sock.exists():
                    break
                await asyncio.sleep(0.05)
            assert sock.exists()
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
