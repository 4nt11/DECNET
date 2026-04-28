"""Canary tokens — decoy artifacts planted in decky filesystems.

Public surface is exported here so callers can ``from decnet.canary
import CanaryArtifact, get_generator, get_instrumenter`` without
knowing the submodule layout.  Concrete generators / instrumenters
live under :mod:`decnet.canary.generators` and
:mod:`decnet.canary.instrumenters` respectively; the factory keeps
import-time cost down by deferring those imports until first use
(same pattern as :mod:`decnet.intel.factory`).
"""
from __future__ import annotations

from decnet.canary.base import (
    CanaryArtifact,
    CanaryContext,
    CanaryGenerator,
    CanaryInstrumenter,
)
from decnet.canary.factory import (
    KNOWN_GENERATORS,
    KNOWN_INSTRUMENTERS,
    get_generator,
    get_instrumenter,
    pick_instrumenter_for_mime,
)

__all__ = [
    "CanaryArtifact",
    "CanaryContext",
    "CanaryGenerator",
    "CanaryInstrumenter",
    "KNOWN_GENERATORS",
    "KNOWN_INSTRUMENTERS",
    "get_generator",
    "get_instrumenter",
    "pick_instrumenter_for_mime",
]
