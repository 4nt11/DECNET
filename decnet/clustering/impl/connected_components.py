"""Connected-components identity clusterer (v1).

Builds a similarity graph over observations (per-IP attacker rows),
runs connected-components over edges that pass a confidence threshold,
and writes one ``attacker_identities`` row per component.

This module is the **skeleton**. The ``tick`` method is a no-op until
the similarity-graph features land in subsequent commits. Subscribers
on ``identity.>`` see no traffic from this clusterer until the edge
functions are wired in.

Subsequent commits add, in order:

1. Similarity-graph scaffolding (``impl/similarity.py``).
2. High-weight edges (JA3/JA4/HASSH/payload/C2 exact match).
3. Medium-weight edges (command-sequence Jaccard bucketed by UKC phase).
4. Phase-handoff edges (designed for fixture 5).
5. Low-weight edges (credential Jaccard, ASN) — must NOT cluster F1/F2 alone.
6. Revocable merges (``identity.merged`` / ``identity.unmerged``).

Edges MUST stay time-agnostic — fixture 7 proves recency-decay clustering
fragments multi-month APT campaigns.
"""
from __future__ import annotations

from decnet.clustering.base import Clusterer, ClusterResult
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("clustering.connected_components")


class ConnectedComponentsClusterer(Clusterer):
    """Connected-components clusterer.

    Skeleton implementation: ``tick`` is a no-op. Wiring lands in
    subsequent commits.
    """

    name = "connected_components"

    async def tick(self, repo: BaseRepository) -> ClusterResult:
        # No similarity edges defined yet; produce an empty result.
        # Subsequent commits replace this with the real pass.
        return ClusterResult()


__all__ = ["ConnectedComponentsClusterer"]
