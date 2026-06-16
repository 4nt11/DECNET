# SPDX-License-Identifier: AGPL-3.0-or-later
"""Helper for building registry-valid :class:`Observation` records.

Every feature module would otherwise repeat the same Window /
source / evidence_ref boilerplate. This helper centralises it and is
the one place to reach when emission semantics change (e.g. when we
start parametrising windows on a per-primitive basis).
"""
from __future__ import annotations

from typing import Any

from behave_core.spec.envelope import Observation, Window

from decnet.profiler.behave_shell._ctx import SessionContext


def make_observation(
    ctx: SessionContext,
    *,
    primitive: str,
    value: Any,
    confidence: float,
) -> Observation:
    """Build one :class:`Observation` for the whole-session window."""
    return Observation(
        primitive=primitive,
        value=value,
        confidence=confidence,
        window=Window(start_ts=ctx.t_start, end_ts=ctx.t_end),
        source=ctx.source,
        evidence_ref=ctx.evidence_ref,
    )
