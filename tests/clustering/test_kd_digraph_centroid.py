# SPDX-License-Identifier: AGPL-3.0-or-later
"""``_digraph_centroid`` — bitwise-majority rollup of session SimHashes."""
from __future__ import annotations

from decnet.clustering.impl.connected_components import _digraph_centroid
from decnet.util.simhash import from_bytes8, to_bytes8

_ALL_ONES = (1 << 64) - 1


class _FakeRepo:
    """Returns canned digraph observations for one identity."""

    def __init__(self, hash_ints: list[int]) -> None:
        self._values = [to_bytes8(h).hex() for h in hash_ints]

    async def observations_for_identity_primitive(self, identity_uuid, primitive):
        assert primitive == "motor.digraph_simhash"
        return [{"value": v} for v in self._values]


async def test_no_observations_returns_none() -> None:
    assert await _digraph_centroid(_FakeRepo([]), "id") is None


async def test_single_session_centroid_is_that_hash() -> None:
    out = await _digraph_centroid(_FakeRepo([0xDEADBEEFCAFEF00D]), "id")
    assert from_bytes8(out) == 0xDEADBEEFCAFEF00D


async def test_majority_wins_per_bit() -> None:
    # 2 of 3 sessions all-ones → every bit majority-set → all ones.
    out = await _digraph_centroid(_FakeRepo([_ALL_ONES, _ALL_ONES, 0]), "id")
    assert from_bytes8(out) == _ALL_ONES


async def test_tie_is_not_set() -> None:
    # 1-1 tie per bit: majority requires strictly more than half → 0.
    out = await _digraph_centroid(_FakeRepo([_ALL_ONES, 0]), "id")
    assert from_bytes8(out) == 0


async def test_garbage_values_skipped() -> None:
    repo = _FakeRepo([])
    repo._values = ["not-hex-zz", "deadbeef", to_bytes8(_ALL_ONES).hex()]  # only the last is valid
    out = await _digraph_centroid(repo, "id")
    assert from_bytes8(out) == _ALL_ONES
