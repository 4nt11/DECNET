# SPDX-License-Identifier: AGPL-3.0-or-later
"""Charikar SimHash util — determinism, LSH property, byte round-trip."""
from __future__ import annotations

from decnet.util.simhash import from_bytes8, hamming64, simhash64, to_bytes8


def test_empty_or_zero_weight_is_zero() -> None:
    assert simhash64({}) == 0
    assert simhash64({"a": 0, "b": -3}) == 0  # non-positive weights skipped


def test_deterministic() -> None:
    tokens = {"th": 3, "he": 2, "er": 1}
    assert simhash64(tokens) == simhash64(dict(tokens))


def test_near_duplicate_low_hamming() -> None:
    base = {f"dg{i}": (i % 5) + 1 for i in range(40)}
    identical = dict(base)
    perturbed = dict(base)
    perturbed["NEW_PAIR"] = 1  # one extra low-weight token
    assert hamming64(simhash64(base), simhash64(identical)) == 0
    assert hamming64(simhash64(base), simhash64(perturbed)) <= 8


def test_disjoint_high_hamming() -> None:
    a = {f"a{i}": 2 for i in range(30)}
    b = {f"b{i}": 2 for i in range(30)}
    # Unrelated token sets ≈ half the 64 bits differ; comfortably ≥ 20.
    assert hamming64(simhash64(a), simhash64(b)) >= 20


def test_bytes_roundtrip_is_8_bytes() -> None:
    h = simhash64({"x": 1, "y": 2, "z": 5})
    raw = to_bytes8(h)
    assert isinstance(raw, bytes) and len(raw) == 8
    assert from_bytes8(raw) == h
