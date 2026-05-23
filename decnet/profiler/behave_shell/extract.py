# SPDX-License-Identifier: AGPL-3.0-or-later
"""Public extraction entry point.

``extract_session`` is the only function workers call. It builds a
:class:`SessionContext` once and fans the registered feature functions
across it. Pure library: no I/O, no bus, no DB. The worker
(``BEHAVE-INTEGRATION.md`` Phase 4) is responsible for those.
"""
from __future__ import annotations

from typing import Iterable, Iterator

from behave_core.spec.envelope import Observation

from decnet.profiler.behave_shell._ctx import SessionContext, build_session_context
from decnet.profiler.behave_shell._features import FEATURES
from decnet.profiler.behave_shell._parse import AsciinemaEvent

DEFAULT_SOURCE = "decnet/profiler/behave_shell/extract.py"


def extract_session(
    events: Iterable[AsciinemaEvent],
    *,
    sid: str,
    source: str = DEFAULT_SOURCE,
    evidence_ref: str | None = None,
) -> Iterator[Observation]:
    """Yield BEHAVE-SHELL observations for a single session.

    ``events`` is an iterable of ``(t, kind, data)`` tuples — see
    ``_parse.AsciinemaEvent``. ``sid`` identifies the session for
    evidence pointers and downstream joins.
    """
    ctx = build_session_context(
        events, sid=sid, source=source, evidence_ref=evidence_ref
    )
    for feature_fn in FEATURES:
        yield from feature_fn(ctx)


def build_context(
    events: Iterable[AsciinemaEvent],
    *,
    sid: str,
    source: str = DEFAULT_SOURCE,
    evidence_ref: str | None = None,
) -> SessionContext:
    """Expose the SessionContext build for tests + future debug tools."""
    return build_session_context(
        events, sid=sid, source=source, evidence_ref=evidence_ref
    )
