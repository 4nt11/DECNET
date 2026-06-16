# SPDX-License-Identifier: AGPL-3.0-or-later
"""In-memory vector store backend.

Two flavors:

* :class:`FakeVectorStore` — a real, working in-memory store. Used by
  tests and by dev environments that want similarity search without
  any native extension on the box. KNN is brute-force L2 — fine up to
  a few thousand vectors per kind.
* :class:`NullVectorStore` — a no-op store returned by the factory
  when ``DECNET_VECTORSTORE_ENABLED=false``. Every method succeeds
  trivially; ``get`` and ``knn`` return None / [] respectively. Lets
  workers run unaffected when the operator hasn't opted into vector
  features yet.
"""
from __future__ import annotations

import math
from typing import Optional, Sequence

from decnet.vectorstore.base import BaseVectorStore, Neighbor, VectorRecord


class FakeVectorStore(BaseVectorStore):
    """Pure-python in-memory vector store, brute-force KNN.

    Suitable for tests and small-scale dev (≤ a few thousand vectors
    per kind). Not persistent — every process restart drops state.
    """

    def __init__(self) -> None:
        # {kind: {id: VectorRecord}}
        self._store: dict[str, dict[str, VectorRecord]] = {}
        # {kind: dim} — locked the first time a kind is written.
        self._dims: dict[str, int] = {}

    async def initialize(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def health(self) -> dict:
        total = sum(len(by_id) for by_id in self._store.values())
        return {
            "ok": True,
            "backend": "fake",
            "kinds": len(self._store),
            "vectors": total,
        }

    async def insert(
        self,
        kind: str,
        id: str,
        vector: Sequence[float],
        *,
        extractor_version: int = 1,
    ) -> None:
        dim = len(vector)
        existing_dim = self._dims.get(kind)
        if existing_dim is None:
            self._dims[kind] = dim
        elif existing_dim != dim:
            raise ValueError(
                f"vector dim mismatch for kind={kind!r}: "
                f"expected {existing_dim}, got {dim}"
            )
        rec = VectorRecord(
            kind=kind, id=id, vector=tuple(float(x) for x in vector),
            dim=dim, extractor_version=int(extractor_version),
        )
        self._store.setdefault(kind, {})[id] = rec

    async def get(self, kind: str, id: str) -> Optional[VectorRecord]:
        return self._store.get(kind, {}).get(id)

    async def delete(self, kind: str, id: str) -> bool:
        bucket = self._store.get(kind)
        if bucket is None or id not in bucket:
            return False
        del bucket[id]
        return True

    async def knn(
        self, kind: str, vector: Sequence[float], k: int = 10
    ) -> list[Neighbor]:
        bucket = self._store.get(kind)
        if not bucket:
            return []
        q = tuple(float(x) for x in vector)
        if len(q) != self._dims.get(kind, len(q)):
            raise ValueError(
                f"query dim {len(q)} != stored dim {self._dims[kind]} "
                f"for kind={kind!r}"
            )
        scored: list[Neighbor] = []
        for rid, rec in bucket.items():
            d = math.sqrt(sum((a - b) ** 2 for a, b in zip(q, rec.vector)))
            scored.append(Neighbor(kind=kind, id=rid, distance=d))
        scored.sort(key=lambda n: n.distance)
        return scored[: max(0, int(k))]


class NullVectorStore(BaseVectorStore):
    """No-op vector store. Returned when vectorstore is disabled."""

    async def initialize(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def health(self) -> dict:
        return {"ok": True, "backend": "null", "kinds": 0, "vectors": 0}

    async def insert(
        self, kind: str, id: str, vector: Sequence[float],
        *, extractor_version: int = 1,
    ) -> None:
        return None

    async def get(self, kind: str, id: str) -> Optional[VectorRecord]:
        return None

    async def delete(self, kind: str, id: str) -> bool:
        return False

    async def knn(
        self, kind: str, vector: Sequence[float], k: int = 10
    ) -> list[Neighbor]:
        return []
