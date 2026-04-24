"""GeoIP provider protocol.

Concrete providers (:mod:`decnet.geoip.rir`, future ``dbip``, ``maxmind``)
implement this. Callers must go through
:func:`~decnet.geoip.factory.get_provider`; never import a concrete
provider class directly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Sequence

from decnet.geoip.lookup import Lookup


class Provider(ABC):
    """Abstract GeoIP data provider."""

    #: Short tag written to ``Attacker.country_source`` (e.g. ``'rir'``).
    name: str

    @abstractmethod
    def refresh(self) -> None:
        """Download / regenerate the provider's raw data files."""

    @abstractmethod
    def build_lookup(self) -> Lookup:
        """Parse the on-disk data files and return a ready-to-query Lookup."""

    @abstractmethod
    def data_paths(self) -> Sequence[Path]:
        """Return the list of files this provider manages — used for staleness
        detection. Order is not significant."""
