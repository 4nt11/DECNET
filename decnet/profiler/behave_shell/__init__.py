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

__all__ = ["DEFAULT_SOURCE", "build_context", "extract_session"]
