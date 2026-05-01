"""Parametrized ``rule_store`` fixture for E.2.14b.

The conformance contract from ``development/TTP_TAGGING.md`` §E.2.14b:
both backends — :class:`FilesystemRuleStore` and
:class:`DatabaseRuleStore` — must satisfy the same observable
behavior. Tests that consume :func:`rule_store` are run twice, once
per backend.

Filesystem is skipped on non-Linux (it raises ``RuntimeError`` from
``__init__`` on macOS / Windows because the inotify dep is
Linux-only).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest

from decnet.ttp.store.base import RuleStore
from decnet.ttp.store.impl.database import DatabaseRuleStore
from decnet.ttp.store.impl.filesystem import FilesystemRuleStore


@pytest.fixture(
    params=["filesystem", "database"],
    ids=["filesystem", "database"],
)
def rule_store(
    request: pytest.FixtureRequest, tmp_path: Path,
) -> Iterator[RuleStore]:
    """Yield a fresh :class:`RuleStore` instance per parametrization.

    The filesystem backend is constructed against a ``tmp_path``
    rules dir so tests never touch the real ``./rules/``. The
    database backend's connection wiring lands at E.3.6; today the
    fixture just hands out the raw class instance and impl-phase
    tests are responsible for plumbing it into a session.
    """
    backend = request.param
    if backend == "filesystem":
        if sys.platform != "linux":
            pytest.skip("FilesystemRuleStore requires Linux (inotify)")
        yield FilesystemRuleStore(rules_dir=tmp_path)
    else:
        yield DatabaseRuleStore()
