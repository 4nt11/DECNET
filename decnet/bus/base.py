# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bus abstractions: the :class:`Event` envelope and the :class:`BaseBus` ABC.

Every transport (NATS, in-process fake, null) speaks this contract.  The
envelope is versioned (``v``) so future evolution never breaks deployed
consumers that happen to see a newer event shape.

Subscription model: :meth:`BaseBus.subscribe` returns a :class:`Subscription`
that is an async context manager AND an async iterator.  The expected usage is:

    async with bus.subscribe("topology.*.mutation.*") as sub:
        async for event in sub:
            handle(event)

Leaving the ``async with`` releases the underlying subscription handle; the
transport is free to drop any buffered events after that point.
"""
from __future__ import annotations

import abc
import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, cast

EVENT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Event:
    """The bus envelope.

    ``v`` is the envelope schema version, bumped on incompatible shape
    changes.  ``type`` is a short discriminator (``"mutation.applied"``,
    ``"decky.state"``) useful for consumers that subscribe to a broad
    wildcard and dispatch in Python; it is redundant with the trailing
    segments of ``topic`` but cheaper to inspect.  ``ts`` is epoch seconds
    (float).  ``id`` is a random UUID so consumers can de-dupe if they
    ever see the same event twice (not expected at-most-once, but cheap
    insurance).
    """

    topic: str
    payload: dict[str, Any]
    type: str = ""
    v: int = EVENT_SCHEMA_VERSION
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "id": self.id,
            "topic": self.topic,
            "type": self.type,
            "ts": self.ts,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, topic: str, data: dict[str, Any]) -> "Event":
        """Reconstruct an Event from a wire-format dict.

        ``topic`` is passed explicitly because the transport knows which
        subject the message arrived on; trusting a ``topic`` field from the
        wire would let a misbehaving publisher spoof events on topics they
        don't actually publish to.
        """
        return cls(
            topic=topic,
            payload=data.get("payload", {}) or {},
            type=data.get("type", "") or "",
            v=int(data.get("v", EVENT_SCHEMA_VERSION)),
            ts=float(data.get("ts", time.time())),
            id=data.get("id") or uuid.uuid4().hex,
        )


class Subscription(abc.ABC):
    """An open subscription — async context manager + async iterator.

    Concrete transports subclass this and implement :meth:`_aclose` plus the
    async iterator protocol.  Callers should not instantiate directly; use
    :meth:`BaseBus.subscribe`.
    """

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self._closed = False

    async def __aenter__(self) -> "Subscription":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    def __aiter__(self) -> AsyncIterator[Event]:
        return self

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._aclose()

    @abc.abstractmethod
    async def __anext__(self) -> Event:  # pragma: no cover - abstract
        raise NotImplementedError

    @abc.abstractmethod
    async def _aclose(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


class BaseBus(abc.ABC):
    """Pub/sub transport contract.

    Implementations MUST be safe to ``await connect()`` multiple times and
    ``await close()`` multiple times.  Publishing to a closed bus raises
    :class:`RuntimeError`; subscribing to a closed bus does too.
    """

    @abc.abstractmethod
    async def connect(self) -> None:
        """Establish any network/transport resources.  Idempotent."""

    @abc.abstractmethod
    async def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        event_type: str = "",
    ) -> None:
        """Publish *payload* on *topic*.  Fire-and-forget.

        Delivery is at-most-once.  On transport error the implementation
        logs and returns; it does not raise, because bus losses must not
        cascade into worker failure (DB is source of truth).
        """

    @abc.abstractmethod
    def subscribe(self, pattern: str) -> Subscription:
        """Return a :class:`Subscription` that yields events matching *pattern*.

        Patterns follow NATS wildcard semantics: ``*`` matches one topic
        token, ``>`` matches one-or-more trailing tokens.  Examples:

        * ``topology.*.mutation.applied`` — all ``applied`` events for any
          topology.
        * ``topology.abc123.mutation.*`` — all mutation states for one
          topology.
        * ``topology.>`` — every event under the ``topology`` root.
        """

    @abc.abstractmethod
    async def close(self) -> None:
        """Tear down transport resources.  Idempotent."""

    async def __aenter__(self) -> "BaseBus":
        await self.connect()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()


# ─── Wildcard matching shared across in-process transports ───────────────────

def matches(pattern: str, topic: str) -> bool:
    """Return True iff *topic* matches *pattern* under NATS wildcard rules.

    ``*`` matches exactly one non-empty token; ``>`` matches one-or-more
    trailing tokens (so ``topology.>`` matches ``topology.abc.x`` but not
    ``topology`` alone).
    """
    p_tokens = pattern.split(".")
    t_tokens = topic.split(".")
    for i, p in enumerate(p_tokens):
        if p == ">":
            # Must have at least one token remaining to match.
            return i < len(t_tokens)
        if i >= len(t_tokens):
            return False
        if p == "*":
            if not t_tokens[i]:
                return False
            continue
        if p != t_tokens[i]:
            return False
    return len(p_tokens) == len(t_tokens)


# Sentinel used by the in-process transports to signal "no more events"
# through the asyncio.Queue fan-out without inventing a separate control
# channel.  Not part of the wire protocol.
_CLOSE_SENTINEL: Any = object()


async def _next_or_stop(queue: "asyncio.Queue[Any]") -> Event:
    """Pop the next item from *queue*, raising ``StopAsyncIteration`` on close."""
    item = await queue.get()
    if item is _CLOSE_SENTINEL:
        raise StopAsyncIteration
    return cast(Event, item)
