# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vector-store abstractions: :class:`BaseVectorStore` ABC + record types.

Every backend (sqlite-vec, in-memory fake, future pgvector / Qdrant)
speaks this contract. The store is keyed by ``(kind, id)`` where:

* ``kind`` is a short discriminator (``ja3``, ``hassh``,
  ``keystroke_dwell``, ``cmd_ngram``, ...) — vectors are only ever
  compared **within the same kind**, so adding a new feature family is
  a non-event for the store.
* ``id`` is a stable identifier owned by the caller — typically the
  ``session_id`` or ``attacker_uuid``. The store does not interpret it.
* ``extractor_version`` is recorded alongside the vector so v1 vs v2 of
  the same kind never get cross-compared by accident — a similarity
  scorer that respects versioning is the consumer's responsibility, but
  the data it needs is here.

The contract is intentionally minimal (insert/get/knn/delete/health) so
backends with different physical layouts can implement it
straightforwardly. No batch APIs in v1 — sub-millisecond per-vector
overhead at honeypot scales (≤ 100k vectors per kind) makes batching
unnecessary, and the loop-over-singles pattern keeps the contract small.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional, Sequence

# Bumped when the wire/ABI shape of records changes incompatibly.
# Backends MAY refuse to load older data when this changes, but the
# pre-v1 expectation is to migrate forward in the same release.
VECTORSTORE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class VectorRecord:
    """One stored vector, returned by :meth:`BaseVectorStore.get`."""

    kind: str
    id: str
    vector: Sequence[float]
    dim: int
    extractor_version: int = 1


@dataclass(frozen=True)
class Neighbor:
    """One similarity-search hit, returned by :meth:`BaseVectorStore.knn`.

    ``distance`` is whatever the backend's native metric reports —
    cosine distance for sqlite-vec's default index, L2 for the in-memory
    fake. Smaller is more similar in both cases. Consumers that need
    a uniform metric should configure the backend explicitly.
    """

    kind: str
    id: str
    distance: float


class BaseVectorStore(abc.ABC):
    """Async interface for a kind-discriminated vector store.

    Implementations MAY be transactional (sqlite) or not (pure
    in-memory). All methods are async to match the rest of the DECNET
    storage layer; trivial backends can ``await`` no-op coroutines.
    """

    @abc.abstractmethod
    async def initialize(self) -> None:
        """One-shot setup (open files, load extensions, create tables)."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Release resources. Idempotent."""

    @abc.abstractmethod
    async def health(self) -> dict:
        """Liveness + capability probe.

        Returns a dict like ``{"ok": True, "backend": "sqlite_vec",
        "kinds": 4, "vectors": 12_345}``. Used by ``/api/v1/health`` and
        diagnostics; never raises — backends that can't determine a
        field set it to None.
        """

    @abc.abstractmethod
    async def insert(
        self,
        kind: str,
        id: str,
        vector: Sequence[float],
        *,
        extractor_version: int = 1,
    ) -> None:
        """Insert or replace ``(kind, id)``. Vector dim is fixed per kind
        the first time a kind is seen; mismatched dims raise.
        """

    @abc.abstractmethod
    async def get(self, kind: str, id: str) -> Optional[VectorRecord]:
        """Fetch one record, or None if absent."""

    @abc.abstractmethod
    async def delete(self, kind: str, id: str) -> bool:
        """Delete one record. Returns True if a row was removed."""

    @abc.abstractmethod
    async def knn(
        self, kind: str, vector: Sequence[float], k: int = 10
    ) -> list[Neighbor]:
        """Return up to *k* nearest neighbors of ``vector`` within
        ``kind``. Empty list if the kind is unknown or empty.
        """
