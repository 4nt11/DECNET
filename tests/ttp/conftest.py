# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared TTP test fixtures.

Forces OTEL tracing ON for all tests in ``tests/ttp/``. Without this
shim :mod:`decnet.telemetry` evaluates ``_ENABLED`` once at import
time from the ``DECNET_DEVELOPER_TRACING`` env var; if the suite is
invoked without that var set, every call to ``get_tracer()`` returns
the no-op stand-in and span-emission tests (E.2.14a, future E.3
impl tests) silently capture nothing.

Two complementary moves:

1. Set ``DECNET_DEVELOPER_TRACING=true`` in :func:`os.environ` before
   any tests run. Catches the case where a fresh import of
   ``decnet.telemetry`` happens after collection.
2. Mutate the already-imported ``decnet.telemetry._ENABLED`` flag to
   ``True``. Catches the case where the module was already imported
   (e.g. by another test or fixture) before this conftest ran —
   reload-and-pray races are nasty enough to hardcode the override.

Both are session-scoped and autouse — the cost of an active OTEL
provider in unrelated tests is negligible (the SDK no-ops when no
processor is attached).
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def _enable_decnet_tracing() -> None:
    """Force ``DECNET_DEVELOPER_TRACING=true`` for the test session.

    Set env var first (covers late imports), then poke
    ``decnet.telemetry._ENABLED`` directly (covers already-imported
    case). Either alone is racy; both together is robust.
    """
    os.environ["DECNET_DEVELOPER_TRACING"] = "true"
    import decnet.telemetry as _t  # noqa: PLC0415 — fixture-time import
    _t._ENABLED = True
