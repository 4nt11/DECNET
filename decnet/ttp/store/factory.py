"""Rule store factory.

Mirrors :mod:`decnet.ttp.factory` and :mod:`decnet.intel.factory`:
callers obtain the active store via :func:`get_rule_store` rather than
instantiating a concrete class. The selected backend is whatever
``DECNET_TTP_RULE_STORE_TYPE`` resolves to (default ``"filesystem"``).

Configuration:

* ``DECNET_TTP_RULE_STORE_TYPE`` — ``"filesystem"`` (Linux-only) or
  ``"database"`` (any platform). Unknown values raise
  :class:`ValueError`.
"""
from __future__ import annotations

import os
from typing import Final

from decnet.ttp.store.base import RuleStore

_KNOWN: Final[tuple[str, ...]] = ("filesystem", "database")
_DEFAULT: Final[str] = "filesystem"


def get_rule_store() -> RuleStore:
    """Return the configured rule store instance.

    The filesystem backend imports :mod:`asyncinotify` at construction
    time and refuses to run on non-Linux platforms (per TTP_TAGGING.md
    §"Linux-only worker host"). macOS / Windows developers running the
    test suite set ``DECNET_TTP_RULE_STORE_TYPE=database``.
    """
    name = os.environ.get(
        "DECNET_TTP_RULE_STORE_TYPE", _DEFAULT,
    ).strip().lower()
    if name == "filesystem":
        from decnet.ttp.store.impl.filesystem import FilesystemRuleStore
        return FilesystemRuleStore()
    if name == "database":
        from decnet.ttp.store.impl.database import DatabaseRuleStore
        return DatabaseRuleStore()
    raise ValueError(
        f"Unknown rule store: {name!r}. Known: {_KNOWN}"
    )


__all__ = ["get_rule_store"]
