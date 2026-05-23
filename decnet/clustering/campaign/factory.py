# SPDX-License-Identifier: AGPL-3.0-or-later
"""Campaign-clusterer factory.

Mirrors :mod:`decnet.clustering.factory` for the campaign layer.
Configuration knob ``DECNET_CAMPAIGN_CLUSTERER_TYPE``; default
``"connected_components"``.
"""
from __future__ import annotations

import os

from decnet.clustering.campaign.base import CampaignClusterer

_KNOWN: tuple[str, ...] = ("connected_components",)
_DEFAULT = "connected_components"


def get_campaign_clusterer() -> CampaignClusterer:
    name = os.environ.get(
        "DECNET_CAMPAIGN_CLUSTERER_TYPE", _DEFAULT,
    ).strip().lower()
    if name == "connected_components":
        from decnet.clustering.campaign.impl.connected_components import (
            ConnectedComponentsCampaignClusterer,
        )
        return ConnectedComponentsCampaignClusterer()
    raise ValueError(
        f"Unknown campaign clusterer: {name!r}. Known: {_KNOWN}"
    )


__all__ = ["get_campaign_clusterer"]
