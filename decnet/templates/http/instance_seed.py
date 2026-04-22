#!/usr/bin/env python3
"""
Per-instance stealth seeding for honeypot service templates.

The whole decoy fleet looks identical to a scanner unless each decky
diverges on the boring details: cluster UUIDs, auth salts, uptime, minor
version strings, etc. This module derives a stable per-instance seed
from NODE_NAME (+ optional INSTANCE_ID) and exposes helpers that return
deterministic-per-decky-but-different-across-the-fleet values.

Connection-time jitter is intentionally NOT seeded — two hits to the same
decky should not replay the same latency curve.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import random
import time
import uuid
from typing import Sequence, TypeVar

T = TypeVar("T")

_HOSTNAME = (
    os.environ.get("NODE_NAME")
    or os.environ.get("HOSTNAME")
    or "decky"
)
_INSTANCE_ID = os.environ.get("INSTANCE_ID", "")
_SEED_MATERIAL = f"{_HOSTNAME}:{_INSTANCE_ID}".encode()
_SEED_INT = int.from_bytes(hashlib.sha256(_SEED_MATERIAL).digest()[:8], "big")

#: Deterministic RNG seeded per decky — use for *persistent* choices
#: (versions, UUIDs, stored credentials). Never use for timing.
rng = random.Random(_SEED_INT)

#: Process boot time — real uptime elapsed since container start.
_PROCESS_START = time.time()

#: Deterministic per-instance fake "has been up for this long at boot"
#: offset, so every decky pretends to have a different history.
_BOOT_OFFSET = rng.randint(3600, 45 * 86400)


def hostname() -> str:
    return _HOSTNAME


def uptime_seconds() -> int:
    """Monotonically increasing, unique per instance."""
    return int(_BOOT_OFFSET + (time.time() - _PROCESS_START))


def boot_epoch() -> int:
    """Fake wall-clock boot time for this instance (seconds since epoch)."""
    return int(time.time() - uptime_seconds())


def instance_uuid(namespace: str = "") -> str:
    """Deterministic UUID4-looking value for this instance+namespace."""
    ns = uuid.UUID("00000000-0000-0000-0000-000000000000")
    return str(uuid.uuid5(ns, f"{_HOSTNAME}:{namespace}"))


def instance_hex(nbytes: int, namespace: str = "") -> str:
    """Deterministic hex token of given byte length."""
    material = f"{_HOSTNAME}:{namespace}".encode()
    digest = hashlib.sha256(material).digest()
    while len(digest) < nbytes:
        digest += hashlib.sha256(digest).digest()
    return digest[:nbytes].hex()


def pick(choices: Sequence[T]) -> T:
    """Deterministic choice from a sequence."""
    return rng.choice(list(choices))


def pick_weighted(choices: Sequence[tuple[T, float]]) -> T:
    """Deterministic weighted choice. Input: [(item, weight), ...]."""
    total = sum(w for _, w in choices)
    r = rng.uniform(0, total)
    acc = 0.0
    for item, w in choices:
        acc += w
        if r <= acc:
            return item
    return choices[-1][0]


def random_bytes(n: int, namespace: str = "") -> bytes:
    """Deterministic per-instance byte string of length n."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out.extend(
            hashlib.sha256(f"{_HOSTNAME}:{namespace}:{i}".encode()).digest()
        )
        i += 1
    return bytes(out[:n])


def fresh_bytes(n: int) -> bytes:
    """Non-deterministic random bytes — for per-connection nonces/salts."""
    return os.urandom(n)


async def jitter(min_ms: int = 5, max_ms: int = 120) -> None:
    """Async response-time jitter. Uses unseeded RNG so timing varies
    across connections to the same decky — seeded jitter would leak
    predictability."""
    await asyncio.sleep(random.uniform(min_ms, max_ms) / 1000.0)


def jitter_sync(min_ms: int = 5, max_ms: int = 120) -> None:
    """Blocking jitter for non-asyncio servers."""
    time.sleep(random.uniform(min_ms, max_ms) / 1000.0)
