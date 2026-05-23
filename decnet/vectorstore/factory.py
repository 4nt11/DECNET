# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vectorstore factory — selects a :class:`BaseVectorStore` implementation.

Dispatch keys:

* ``DECNET_VECTORSTORE_ENABLED`` — ``"false"`` short-circuits to
  :class:`~decnet.vectorstore.fake.NullVectorStore`. Default ``"true"``.
* ``DECNET_VECTORSTORE_TYPE`` — ``"sqlite_vec"`` (default) or
  ``"fake"``.
* ``DECNET_VECTORSTORE_PATH`` — sqlite file path. Defaults to
  ``/var/lib/decnet/vectors.sqlite`` if writable, else
  ``~/.decnet/vectors.sqlite``.

Mirrors :mod:`decnet.bus.factory` and :mod:`decnet.web.db.factory`:
lazy imports inside each branch, env-driven dispatch, callers MUST go
through :func:`get_vectorstore` rather than instantiating backends.

If ``sqlite_vec`` is requested but the extension is unavailable on
this host, the factory logs a warning and returns the fake backend
instead — the caller's code path stays valid (``insert`` no-ops, etc.)
without crashing the worker on a missing optional dependency.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from decnet.vectorstore.base import BaseVectorStore

LOG = logging.getLogger(__name__)


def get_vectorstore(**kwargs: Any) -> BaseVectorStore:
    if os.environ.get("DECNET_VECTORSTORE_ENABLED", "true").lower() == "false":
        from decnet.vectorstore.fake import NullVectorStore
        return NullVectorStore()

    backend = os.environ.get("DECNET_VECTORSTORE_TYPE", "sqlite_vec").lower()

    if backend == "fake":
        from decnet.vectorstore.fake import FakeVectorStore
        return FakeVectorStore()

    if backend == "sqlite_vec":
        # Probe extension availability up front so the factory can fall
        # back cleanly. Construction is cheap, but the extension load
        # only happens in initialize(); without this probe the caller
        # sees the failure too late to substitute a backend.
        try:
            import sqlite_vec  # noqa: F401
        except ImportError as e:
            LOG.warning(
                "sqlite_vec not installed (%s); falling back to FakeVectorStore. "
                "Install the sqlite-vec package or set "
                "DECNET_VECTORSTORE_TYPE=fake to silence this warning.", e,
            )
            from decnet.vectorstore.fake import FakeVectorStore
            return FakeVectorStore()
        from decnet.vectorstore.sqlite_vec import SqliteVecVectorStore
        db_path = kwargs.pop("db_path", None) or _default_db_path()
        return SqliteVecVectorStore(db_path=db_path)

    raise ValueError(f"Unsupported vectorstore type: {backend}")


def _default_db_path() -> str:
    explicit = os.environ.get("DECNET_VECTORSTORE_PATH")
    if explicit:
        return explicit
    runtime_dir = "/var/lib/decnet"
    if os.path.isdir(runtime_dir) and os.access(runtime_dir, os.W_OK):
        return f"{runtime_dir}/vectors.sqlite"
    return os.path.expanduser("~/.decnet/vectors.sqlite")
