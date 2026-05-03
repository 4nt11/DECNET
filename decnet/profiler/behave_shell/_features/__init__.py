"""Registered feature functions.

Each entry takes a ``SessionContext`` and yields zero or more
``Observation`` instances. Adding a primitive = adding a function in a
sibling module and appending it to ``FEATURES``.

Step 0 ships an empty tuple — extract_session() is wired but emits
nothing until Step 2.
"""
from __future__ import annotations

from typing import Callable, Iterable

from decnet_behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext

FeatureFn = Callable[[SessionContext], Iterable[Observation]]

FEATURES: tuple[FeatureFn, ...] = ()
