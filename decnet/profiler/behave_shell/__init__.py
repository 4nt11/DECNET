# SPDX-License-Identifier: AGPL-3.0-or-later
"""BEHAVE-SHELL extraction engine — DECNET's official implementation.

Per ``development/BEHAVE-EXTRACTOR.md``: this package is a pure
library. Workers (``BEHAVE-INTEGRATION.md`` Phase 4) own I/O, bus
emission, and persistence. The engine just turns one PTY session into
``Iterable[Observation]``.

BEHAVE is the spec; DECNET is the engine.
"""
from __future__ import annotations

from decnet.profiler.behave_shell.extract import (
    DEFAULT_SOURCE,
    build_context,
    extract_session,
)

# Phase H.5-pre: extractor is feature-complete (37/37 Tier-A primitives
# emit; calibration grid honest). The ``-pre`` suffix stays until
# ``BEHAVE-INTEGRATION.md`` Phase 4 lands the worker wiring + observations
# table writes + AttackerDetail panel; only then does H.5 proper drop the
# suffix and tag v0.
__version__ = "0.1.0-pre"

__all__ = ["DEFAULT_SOURCE", "build_context", "extract_session", "__version__"]
