# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end tests for :class:`UnixSocketBus` against a real :class:`BusServer`.

These tests run in the dev loop (no pytest marker) because they only need
the tmp filesystem — no Docker, no external broker.
"""
from __future__ import annotations

import asyncio
import contextlib
import pathlib
import stat

import pytest

from decnet.bus.unix_client import UnixSocketBus
from decnet.bus.unix_server import BusServer


async def _drain(sub, n: int, timeout: float = 1.5) -> list:
    out = []
    try:
        async with asyncio.timeout(timeout):
            async for event in sub:
                out.append(event)
                if len(out) >= n:
                    break
    except TimeoutError:
        pass
    return out


class TestEndToEnd:
    async def test_pub_sub_exact(self, unix_bus) -> None:
        server, client = unix_bus
        sub = client.subscribe("topology.abc.status")
        # Give the SUB frame a tick to register on the server.
        await asyncio.sleep(0.05)
        async with sub:
            await client.publish("topology.abc.status", {"status": "active"})
            events = await _drain(sub, 1)
        # A publisher doesn't see its own events — use a second client.
        assert events == []

    async def test_pub_sub_across_two_clients(
        self, tmp_path: pathlib.Path,
    ) -> None:
        sock = tmp_path / "bus.sock"
        server = BusServer(sock, group=None)
        await server.start()
        serve_task = asyncio.create_task(server.serve_forever())

        publisher = UnixSocketBus(sock, client_name="publisher")
        subscriber = UnixSocketBus(sock, client_name="subscriber")
        await publisher.connect()
        await subscriber.connect()

        try:
            sub = subscriber.subscribe("topology.*.mutation.*")
            await asyncio.sleep(0.05)  # let SUB register

            async with sub:
                await publisher.publish(
                    "topology.t1.mutation.applied", {"id": 1}, event_type="applied",
                )
                await publisher.publish(
                    "decky.xyz.state", {"state": "running"},  # should not match
                )
                await publisher.publish(
                    "topology.t2.mutation.failed", {"id": 2}, event_type="failed",
                )
                events = await _drain(sub, 2)
            ids = {e.payload["id"] for e in events}
            assert ids == {1, 2}
        finally:
            await publisher.close()
            await subscriber.close()
            serve_task.cancel()
            try:
                await serve_task
            except asyncio.CancelledError:
                pass
            await server.close()

    async def test_socket_file_mode(self, tmp_path: pathlib.Path) -> None:
        sock = tmp_path / "bus.sock"
        server = BusServer(sock, group=None)
        await server.start()
        try:
            mode = stat.S_IMODE(sock.stat().st_mode)
            assert mode == 0o660
        finally:
            await server.close()

    async def test_server_close_wakes_subscribers(
        self, tmp_path: pathlib.Path,
    ) -> None:
        sock = tmp_path / "bus.sock"
        server = BusServer(sock, group=None)
        await server.start()
        serve_task = asyncio.create_task(server.serve_forever())

        client = UnixSocketBus(sock, client_name="watcher")
        await client.connect()
        sub = client.subscribe("system.>")
        await asyncio.sleep(0.05)

        async def consume() -> list:
            out = []
            async for event in sub:
                out.append(event)
            return out

        consumer = asyncio.create_task(consume())
        await asyncio.sleep(0.05)

        serve_task.cancel()
        try:
            await serve_task
        except asyncio.CancelledError:
            pass
        await server.close()

        # The consumer must unblock within a reasonable time.
        events = await asyncio.wait_for(consumer, timeout=1.0)
        assert events == []
        await client.close()

    async def test_start_rejects_missing_parent(self, tmp_path: pathlib.Path) -> None:
        sock = tmp_path / "nonexistent-dir" / "bus.sock"
        server = BusServer(sock, group=None)
        with pytest.raises(FileNotFoundError):
            await server.start()


class TestConcurrentConnect:
    """BUG-5: connect() must hold the bus lock so concurrent first-connects
    can't each open a socket and spawn a reader (orphaning the loser's FD +
    reader_loop task)."""

    async def test_concurrent_connect_opens_one_socket_and_reader(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sock = tmp_path / "bus.sock"
        server = BusServer(sock, group=None)
        await server.start()
        serve_task = asyncio.create_task(server.serve_forever())

        bus = UnixSocketBus(sock, client_name="race-client")

        # Wrap the real transport opener with a counter, and yield control
        # mid-open so two racing connect() calls actually interleave. Without
        # the lock both would pass the `self._writer is None` guard and each
        # open a socket; the lock + re-check collapse that to one open.
        real_open = asyncio.open_unix_connection
        calls = 0

        async def _counting_open(*args, **kwargs):
            nonlocal calls
            calls += 1
            await asyncio.sleep(0)  # force the scheduler to interleave callers
            return await real_open(*args, **kwargs)

        monkeypatch.setattr(asyncio, "open_unix_connection", _counting_open)

        try:
            await asyncio.gather(bus.connect(), bus.connect(), bus.connect())

            # Exactly one socket opened and exactly one live reader task.
            assert calls == 1
            assert bus._writer is not None
            assert bus._reader_task is not None
            assert not bus._reader_task.done()
        finally:
            await bus.close()
            serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await serve_task
            await server.close()

        # close() reaped the single reader task — no orphans left behind.
        assert bus._reader_task is None
