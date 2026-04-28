"""Campaign clusterer protocol — layer above identity resolution.

Mirrors :mod:`decnet.clustering.base` for the layer above. Each concrete
campaign clusterer implements :class:`CampaignClusterer`; callers obtain
the active instance via
:func:`decnet.clustering.campaign.factory.get_campaign_clusterer`.

The result shape parallels :class:`ClusterResult` but speaks campaign
vocabulary: campaigns formed, identities assigned, campaigns merged,
campaigns unmerged.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from decnet.web.db.repository import BaseRepository


@dataclass
class CampaignClusterResult:
    """Side-effects produced by a single campaign-clusterer ``tick``.

    Consumed by the worker shell to publish on the bus
    (``campaign.formed`` / ``campaign.identity.assigned`` /
    ``campaign.merged`` / ``campaign.unmerged`` plus the cross-family
    ``identity.campaign.assigned``).  DB writes are already committed
    by the time this returns.
    """

    campaigns_formed: list[dict[str, Any]] = field(default_factory=list)
    """``{"campaign_uuid": str, "identity_uuids": [str, ...]}``."""

    identities_assigned: list[dict[str, Any]] = field(default_factory=list)
    """``{"campaign_uuid": str, "identity_uuid": str,
    "prior_campaign_uuid": Optional[str]}``."""

    campaigns_merged: list[dict[str, Any]] = field(default_factory=list)
    """``{"winner_uuid": str, "loser_uuid": str}``."""

    campaigns_unmerged: list[dict[str, Any]] = field(default_factory=list)
    """``{"resurrected_uuid": str, "former_winner_uuid": str}``."""


class CampaignClusterer(ABC):
    """Abstract campaign clusterer.

    Single-method contract mirroring :class:`Clusterer`: ``tick`` reads
    identities from the repo, projects them to a campaign-level feature
    shape, runs a clustering pass, commits ``campaigns`` rows + sets
    ``attacker_identities.campaign_id``, and returns a
    :class:`CampaignClusterResult` summarising side-effects.

    Implementations MUST NOT raise from ``tick``: a single bad pass
    cannot be allowed to crash the worker.
    """

    name: str

    @abstractmethod
    async def tick(self, repo: BaseRepository) -> CampaignClusterResult:
        """Run a single campaign clustering pass."""


__all__ = ["CampaignClusterer", "CampaignClusterResult"]
