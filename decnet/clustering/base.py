"""Identity-resolution clusterer protocol.

Each concrete clusterer (``decnet.clustering.impl.connected_components``,
and any future variant) implements this. Callers must obtain the active
clusterer via :func:`decnet.clustering.factory.get_clusterer` — never
instantiate a concrete class directly.

The clusterer mirrors the provider-subpackage convention used by
:mod:`decnet.bus` and :mod:`decnet.web.db`: ``base.py`` defines the
protocol, ``factory.py`` dispatches on ``DECNET_CLUSTERER_TYPE``, and
``impl/`` holds concrete implementations.

Distinct from the ``tests/factories/campaign_factory.py`` namespace —
that's the synthetic-data DSL used by the fixture suite. The clusterer
here is the production worker that the fixture suite *gates*.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from decnet.web.db.repository import BaseRepository


@dataclass
class ClusterResult:
    """Side-effects produced by a single clusterer ``tick``.

    The worker shell consumes these to publish on the bus
    (``identity.formed`` / ``identity.observation.linked`` /
    ``identity.merged`` / ``identity.unmerged``). The clusterer itself
    has already committed any DB writes by the time it returns this —
    losing a publish is at most a few seconds of UI latency.
    """

    identities_formed: list[dict[str, Any]] = field(default_factory=list)
    """One dict per newly created identity. Shape:
    ``{"identity_uuid": str, "observation_uuids": [str, ...]}``."""

    observations_linked: list[dict[str, Any]] = field(default_factory=list)
    """One dict per observation attached to an existing identity. Shape:
    ``{"identity_uuid": str, "observation_uuid": str}``."""

    identities_merged: list[dict[str, Any]] = field(default_factory=list)
    """One dict per merge. Shape: ``{"winner_uuid": str,
    "loser_uuid": str}``."""

    identities_unmerged: list[dict[str, Any]] = field(default_factory=list)
    """One dict per revoked merge (contradicting evidence re-split a
    previously-merged pair). Shape:
    ``{"resurrected_uuid": str, "former_winner_uuid": str}``.

    Reserved for the revocable-merge work; the skeleton clusterer never
    produces these. Subscribers on ``identity.>`` should still handle
    them from day one — see ``identity.unmerged`` in
    :mod:`decnet.bus.topics`.
    """


class Clusterer(ABC):
    """Abstract identity-resolution clusterer.

    Single-method contract: ``tick`` reads pending observations from the
    repo, runs a clustering pass, commits ``attacker_identities`` rows +
    sets ``attackers.identity_id``, and returns a :class:`ClusterResult`
    summarising the side-effects so the worker shell can publish.

    Implementations MUST NOT raise from ``tick``: a single bad pass
    cannot be allowed to crash the worker. Internal failures should be
    logged and the method should return an empty :class:`ClusterResult`.
    """

    #: Short tag — surfaces in logs and in
    #: ``DECNET_CLUSTERER_TYPE`` for factory dispatch.
    name: str

    @abstractmethod
    async def tick(self, repo: BaseRepository) -> ClusterResult:
        """Run a single clustering pass. See class docstring."""


__all__ = ["Clusterer", "ClusterResult"]
