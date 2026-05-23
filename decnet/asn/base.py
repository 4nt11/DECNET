# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASN provider protocol — mirror of :mod:`decnet.geoip.base`.

Concrete providers (e.g. :mod:`decnet.asn.iptoasn`) implement this.
Callers must go through :func:`decnet.asn.factory.get_provider`; never
import a concrete provider class directly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Sequence

from decnet.asn.lookup import AsnLookup


class Provider(ABC):
    """Abstract IP→ASN data provider."""

    #: Short tag written to ``Attacker.asn_source`` (e.g. ``'iptoasn'``).
    name: str

    @abstractmethod
    def refresh(self) -> None:
        """Download / regenerate the provider's raw data files."""

    @abstractmethod
    def build_lookup(self) -> AsnLookup:
        """Parse the on-disk data files and return a ready-to-query lookup."""

    @abstractmethod
    def data_paths(self) -> Sequence[Path]:
        """Return the list of files this provider manages — used for staleness
        detection. Order is not significant."""
