# SPDX-License-Identifier: AGPL-3.0-or-later
"""UNIX-socket client — :class:`UnixSocketBus` implementation of :class:`BaseBus`.

Holds one open socket to the local :class:`~decnet.bus.unix_server.BusServer`.
Operations:

* :meth:`publish` writes a single ``PUB`` frame and returns; no ack.
* :meth:`subscribe` writes a ``SUB`` frame and returns a
  :class:`~decnet.bus.base.Subscription` backed by an :class:`asyncio.Queue`
  that the background reader task feeds.

One background reader task per bus instance dispatches incoming ``EVT``
frames to every registered subscription whose pattern matches the topic.
On connection drop or close, every subscription is woken via a sentinel so
iterators unblock cleanly; callers see :class:`StopAsyncIteration` from the
``async for`` loop.

No auto-reconnect in MVP.  If the server restarts, callers must
:meth:`close` the bus and construct a new one.  This mirrors how other
DECNET workers handle their dependencies — the systemd ``Restart=on-failure``
supervision above us is the retry loop.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import pathlib
from typing import Any

from decnet.bus import protocol
from decnet.bus.base import (
    BaseBus,
    Event,
    Subscription,
    _CLOSE_SENTINEL,
    matches,
)
from decnet.bus.fake import _enqueue_drop_oldest as _enqueue_event_drop_oldest
from decnet.logging import get_logger

log = get_logger("bus.client")

_INBOUND_QUEUE_SIZE = 1024


class _UnixSubscription(Subscription):
    def __init__(
        self,
        bus: "UnixSocketBus",
        pattern: str,
        queue: "asyncio.Queue[Any]",
    ) -> None:
        super().__init__(pattern)
        self._bus = bus
        self._queue = queue

    async def __anext__(self) -> Event:
        if self._closed:
            raise StopAsyncIteration
        item = await self._queue.get()
        if item is _CLOSE_SENTINEL:
            raise StopAsyncIteration
        return item

    async def _aclose(self) -> None:
        await self._bus._unregister(self)
        try:
            self._queue.put_nowait(_CLOSE_SENTINEL)
        except asyncio.QueueFull:
            pass


class UnixSocketBus(BaseBus):
    """Client handle for a local :class:`BusServer`.

    One instance per process typically; multiple instances simply open
    multiple sockets to the same server.  Connection is lazy — the first
    :meth:`connect` (or any publish/subscribe call via ``async with``)
    opens the socket.
    """

    def __init__(
        self,
        socket_path: pathlib.Path | str,
        *,
        client_name: str | None = None,
    ) -> None:
        self._path = pathlib.Path(socket_path)
        self._client_name = client_name or f"decnet-bus-client[{os.getpid()}]"
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._subs: list[_UnixSubscription] = []
        self._lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._closed = False
        # Sticky flag: the first publish-on-closed-bus call logs at
        # WARNING so operators see that a publish was dropped; subsequent
        # calls on the same instance log at DEBUG only to prevent a
        # log flood when stream threads drain after close.  The bus is
        # critical infra, so the first warning is non-negotiable.
        self._closed_publish_warned = False

    # ─── Lifecycle ──────────────────────────────────────────────────────────

    async def connect(self) -> None:
        if self._writer is not None:
            return
        if self._closed:
            raise RuntimeError("connect on closed bus")
        self._reader, self._writer = await asyncio.open_unix_connection(str(self._path))
        await self._send(protocol.encode(protocol.HELLO, args=self._client_name))
        self._reader_task = asyncio.create_task(self._reader_loop())
        log.debug("bus.client: connected to %s as %s", self._path, self._client_name)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        # Best-effort BYE — we don't care if it fails.
        if self._writer is not None and not self._writer.is_closing():
            with contextlib.suppress(Exception):
                await self._send(protocol.encode(protocol.BYE))

        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
            self._reader_task = None

        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
                await self._writer.wait_closed()
            self._writer = None
            self._reader = None

        # Wake every subscription so `async for` exits.
        for sub in list(self._subs):
            with contextlib.suppress(asyncio.QueueFull):
                sub._queue.put_nowait(_CLOSE_SENTINEL)
        self._subs.clear()

    # ─── Pub/Sub ────────────────────────────────────────────────────────────

    async def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        event_type: str = "",
    ) -> None:
        if self._closed:
            # Degrade gracefully: the DB is the source of truth, the bus
            # is only the notification layer.  Raising here made every
            # caller via publish_safely flood the logs once per stream
            # line during shutdown races.  First drop warns loudly;
            # subsequent drops on the same instance are DEBUG-only.
            if not self._closed_publish_warned:
                self._closed_publish_warned = True
                log.warning(
                    "bus.client: publish on closed bus dropped topic=%s "
                    "(further drops on this instance logged at DEBUG)",
                    topic,
                )
            else:
                log.debug("bus.client: publish on closed bus dropped topic=%s", topic)
            return
        if self._writer is None:
            await self.connect()
        body = Event(topic=topic, payload=payload, type=event_type).to_dict()
        try:
            await self._send(protocol.encode(protocol.PUB, args=topic, body=body))
        except (ConnectionError, BrokenPipeError) as exc:
            # Bus loss is a logged warning, never a publisher crash.  The
            # DB-as-source-of-truth invariant means the work is already
            # persisted; the missing event is just a missed notification.
            log.warning("bus.client: publish failed: %s", exc)

    def subscribe(self, pattern: str) -> Subscription:
        if self._closed:
            raise RuntimeError("subscribe on closed bus")
        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=_INBOUND_QUEUE_SIZE)
        sub = _UnixSubscription(self, pattern, queue)
        self._subs.append(sub)
        # Schedule the SUB frame asynchronously so subscribe() stays sync,
        # matching the BaseBus signature.  The caller will shortly `async
        # with` / `async for` the subscription, which will run the event
        # loop and pick this task up.
        asyncio.ensure_future(self._send_sub(pattern))
        return sub

    async def _send_sub(self, pattern: str) -> None:
        try:
            if self._writer is None:
                await self.connect()
            await self._send(protocol.encode(protocol.SUB, args=pattern))
        except Exception as exc:  # pragma: no cover - network paths in live tests
            log.warning("bus.client: SUB %s failed: %s", pattern, exc)

    async def _unregister(self, sub: _UnixSubscription) -> None:
        try:
            self._subs.remove(sub)
        except ValueError:
            return
        # Tell the server we no longer want events for this pattern if no
        # other local subscription still wants it.
        if not any(s.pattern == sub.pattern for s in self._subs):
            with contextlib.suppress(Exception):
                await self._send(protocol.encode(protocol.UNSUB, args=sub.pattern))

    # ─── Internal I/O ───────────────────────────────────────────────────────

    async def _send(self, frame_bytes: bytes) -> None:
        if self._writer is None:
            raise ConnectionError("bus.client: not connected")
        async with self._write_lock:
            self._writer.write(frame_bytes)
            await self._writer.drain()

    async def _reader_loop(self) -> None:
        if self._reader is None:
            return
        try:
            while True:
                frame = await protocol.read_frame(self._reader)
                if frame is None:
                    break
                if frame.verb != protocol.EVT:
                    # Clients only ever legitimately receive EVT (or BYE).
                    if frame.verb == protocol.BYE:
                        break
                    log.warning("bus.client: unexpected verb from server: %s", frame.verb)
                    continue
                topic = frame.args
                data = protocol.decode_body(frame.body) if frame.body else {}
                event = Event.from_dict(topic, data)
                self._dispatch(event)
        except protocol.ProtocolError as exc:
            log.warning("bus.client: protocol error: %s", exc)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover
            log.exception("bus.client: reader loop crashed")
        finally:
            # Server-side close — wake every subscription.
            for sub in list(self._subs):
                with contextlib.suppress(asyncio.QueueFull):
                    sub._queue.put_nowait(_CLOSE_SENTINEL)

    def _dispatch(self, event: Event) -> None:
        for sub in self._subs:
            if matches(sub.pattern, event.topic):
                _enqueue_event_drop_oldest(sub._queue, event)
