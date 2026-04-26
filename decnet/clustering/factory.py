"""Clusterer factory.

Returns the active :class:`~decnet.clustering.base.Clusterer` instance.
Mirrors :mod:`decnet.bus.factory` and :mod:`decnet.web.db.factory`:
callers obtain the clusterer via :func:`get_clusterer` rather than
importing a concrete impl directly.

Configuration knobs (env-overridable):

* ``DECNET_CLUSTERER_TYPE`` — which implementation to use. Default
  ``"connected_components"``. Unknown values raise :class:`ValueError`
  so a typo in ``decnet.ini`` surfaces immediately rather than silently
  falling back.

The ``connected_components`` implementation is the v1 production
clusterer. Other implementations (e.g. an HDBSCAN variant) can land
here later without churning callers.
"""
from __future__ import annotations

import os

from decnet.clustering.base import Clusterer

_KNOWN_CLUSTERERS = ("connected_components",)
_DEFAULT_CLUSTERER = "connected_components"


def get_clusterer() -> Clusterer:
    """Return the configured clusterer instance.

    Lazy-imports the concrete impl so the base module stays free of
    implementation-specific dependencies.
    """
    name = os.environ.get("DECNET_CLUSTERER_TYPE", _DEFAULT_CLUSTERER).strip().lower()
    if name == "connected_components":
        from decnet.clustering.impl.connected_components import (
            ConnectedComponentsClusterer,
        )
        return ConnectedComponentsClusterer()
    raise ValueError(
        f"Unknown clusterer: {name!r}. Known: {_KNOWN_CLUSTERERS}"
    )


__all__ = ["get_clusterer"]
