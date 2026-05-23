# SPDX-License-Identifier: AGPL-3.0-or-later
"""In-process bus transports.

* :class:`FakeBus` — real pub/sub semantics without touching a socket.  Used
  by unit tests and anywhere ``DECNET_BUS_TYPE=fake`` is set.  Lets code
  that depends on the bus be exercised entirely inside a single event loop,
  matching the DECNET testing convention of not opening real network
  sockets from unit tests.
* :class:`NullBus` — no-op.  Returned by :func:`~decnet.bus.factory.get_bus`
  when ``DECNET_BUS_ENABLED=false`` so workers can start cleanly in dev
  environments where no bus daemon is running.  Publishes are dropped;
  subscriptions yield nothing and close cleanly.
"""
from __future__ import annotations

import asyncio
from typing import Any

from decnet.bus.base import (
    BaseBus,
    Event,
    Subscription,
    _CLOSE_SENTINEL,
    matches,
)
from decnet.logging import get_logger

log = get_logger("bus.fake")

# Per-subscriber bounded queue: backpressure policy is drop-oldest so a slow
# consumer cannot stall publishers (the invariant — DB is the source of
# truth — makes dropped events acceptable).
_DEFAULT_QUEUE_SIZE = 1024


# ─── FakeBus ─────────────────────────────────────────────────────────────────


class _FakeSubscription(Subscription):
    """Subscription backed by an :class:`asyncio.Queue` fed from
    :meth:`FakeBus.publish`.  Unregisters itself on close."""

    def __init__(self, bus: "FakeBus", pattern: str, queue: "asyncio.Queue[Any]") -> None:
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
        self._bus._unregister(self)
        # Unblock any pending __anext__ waiter.
        try:
            self._queue.put_nowait(_CLOSE_SENTINEL)
        except asyncio.QueueFull:
            pass


class FakeBus(BaseBus):
    """In-process pub/sub.

    Publishes iterate every active subscription and enqueue the event on
    the ones whose pattern matches the topic.  If a subscriber's queue is
    full, the oldest event is discarded to make room — same at-most-once
    semantics as the real UNIX-socket transport.
    """

    def __init__(self, queue_size: int = _DEFAULT_QUEUE_SIZE) -> None:
        self._queue_size = queue_size
        self._subs: list[_FakeSubscription] = []
        self._connected = False
        self._closed = False
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        self._connected = True

    async def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        event_type: str = "",
    ) -> None:
        if self._closed:
            raise RuntimeError("publish on closed bus")
        event = Event(topic=topic, payload=payload, type=event_type)
        async with self._lock:
            targets = [s for s in self._subs if matches(s.pattern, topic)]
        for sub in targets:
            _enqueue_drop_oldest(sub._queue, event)

    def subscribe(self, pattern: str) -> Subscription:
        if self._closed:
            raise RuntimeError("subscribe on closed bus")
        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=self._queue_size)
        sub = _FakeSubscription(self, pattern, queue)
        self._subs.append(sub)
        return sub

    def _unregister(self, sub: _FakeSubscription) -> None:
        try:
            self._subs.remove(sub)
        except ValueError:
            pass

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Wake every still-open subscription so iterators unblock cleanly.
        for sub in list(self._subs):
            try:
                sub._queue.put_nowait(_CLOSE_SENTINEL)
            except asyncio.QueueFull:
                pass
        self._subs.clear()


def _enqueue_drop_oldest(queue: "asyncio.Queue[Any]", event: Event) -> None:
    """Put *event* on *queue*, dropping the oldest item if the queue is full.

    Factored out so both FakeBus and the real UNIX server share the exact
    same backpressure policy.
    """
    while True:
        try:
            queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            try:
                dropped = queue.get_nowait()
                log.warning(
                    "bus.fake: subscriber queue full, dropped %s", getattr(dropped, "topic", "?")
                )
            except asyncio.QueueEmpty:
                return


# ─── NullBus ─────────────────────────────────────────────────────────────────


class _NullSubscription(Subscription):
    """A subscription that never yields and closes immediately on iteration."""

    async def __anext__(self) -> Event:
        raise StopAsyncIteration

    async def _aclose(self) -> None:
        return


class NullBus(BaseBus):
    """No-op bus used when ``DECNET_BUS_ENABLED=false``.

    Publishes are silently dropped; subscriptions are empty.  Intended for
    dev environments where no bus daemon is running — the process starts
    cleanly, code that publishes doesn't need feature flags, and nothing
    ever blocks on a subscriber.
    """

    async def connect(self) -> None:
        return

    async def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        event_type: str = "",
    ) -> None:
        return

    def subscribe(self, pattern: str) -> Subscription:
        return _NullSubscription(pattern)

    async def close(self) -> None:
        return
