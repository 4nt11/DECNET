# SPDX-License-Identifier: AGPL-3.0-or-later
"""Charikar 64-bit SimHash + Hamming helpers.

Locality-sensitive fingerprint: inputs that share most weighted tokens
produce hashes a few bits apart (small Hamming distance), so near-
duplicates cluster without storing the raw feature vector. Used by the
keystroke-digraph biometric (``decnet/profiler/.../motor.py``) and the
campaign clusterer's typing-similarity edge.

ponytail: ``templates/smtp/server.py:_body_simhash`` is the same
algorithm, inlined to keep slim decky containers from importing decnet.
Left as-is to avoid pulling decnet into decky images; dedup here only if
a third caller appears.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping

_BITS = 64
_MASK = (1 << _BITS) - 1


def simhash64(weighted_tokens: Mapping[str, int]) -> int:
    """Charikar 64-bit SimHash over frequency-weighted tokens.

    Returns 0 on empty/all-zero-weight input — callers treat 0 as "no
    signal". Per-token hash is md5[:8]: a content fingerprint, not a
    security primitive.
    """
    if not weighted_tokens:
        return 0
    bits = [0] * _BITS
    for tok, weight in weighted_tokens.items():
        if weight <= 0:
            continue
        h = int.from_bytes(
            # Content fingerprint, not a security primitive — md5[:8] is fast
            # and 64 bits is all we need; usedforsecurity=False clears B324.
            hashlib.md5(
                tok.encode("utf-8", errors="replace"), usedforsecurity=False,
            ).digest()[:8],
            "big",
        )
        for i in range(_BITS):
            bits[i] += weight if (h >> i) & 1 else -weight
    out = 0
    for i in range(_BITS):
        if bits[i] > 0:
            out |= (1 << i)
    return out


def hamming64(a: int, b: int) -> int:
    """Number of differing bits between two 64-bit ints."""
    return ((a ^ b) & _MASK).bit_count()


def to_bytes8(value: int) -> bytes:
    """64-bit int → 8 big-endian bytes (for ``BINARY(8)`` storage)."""
    return (value & _MASK).to_bytes(8, "big")


def from_bytes8(raw: bytes) -> int:
    """8 big-endian bytes → 64-bit int."""
    return int.from_bytes(raw, "big")
