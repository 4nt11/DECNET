"""DECNET attribution engine — v0 aggregation library.

Pure library: per-(identity, primitive) state machine over BEHAVE-SHELL
observations. No I/O, no bus, no DB. The bus subscriber and DB writes
live in :mod:`decnet.correlation.attribution_worker` so this package
stays trivially testable with synthetic observation lists.

See ``development/ATTRIBUTION-ENGINE.md`` for the full design and the
explicit bright line: this engine does NOT do persona classification
(HUMAN/LLM/SCRIPTED), does NOT gate access, does NOT attribute to
named persons. It surfaces *behavioural coherence* and *behavioural
drift*, and stops there.
"""
from __future__ import annotations

from decnet.correlation.attribution.aggregate import (
    AttributionState,
    aggregate_observations,
)

__all__ = ["AttributionState", "aggregate_observations"]
