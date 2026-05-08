"""Step H.5-pre: extractor ``__version__`` marker.

The version marker is the engine's own identifier; it does NOT need
to track ``decnet-behave-shell`` (the spec library) — they version
independently. v0 of the spec is already shipped; v0 of the engine
ships once worker wiring lands.
"""
from __future__ import annotations

import re

import decnet.profiler.behave_shell as behave_shell


def test_version_marker_present_and_well_formed() -> None:
    assert hasattr(behave_shell, "__version__"), (
        "decnet.profiler.behave_shell must export __version__"
    )
    assert re.match(r"^0\.1\.0(?:-pre)?$", behave_shell.__version__), (
        f"unexpected version: {behave_shell.__version__!r}; "
        "expected 0.1.0 or 0.1.0-pre"
    )


def test_version_in_dunder_all() -> None:
    assert "__version__" in behave_shell.__all__
