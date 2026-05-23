# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for :func:`decnet.vectorstore.factory.get_vectorstore` dispatch."""
from __future__ import annotations

import os

import pytest

from decnet.vectorstore.factory import _default_db_path, get_vectorstore
from decnet.vectorstore.fake import FakeVectorStore, NullVectorStore


def test_disabled_returns_null(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_VECTORSTORE_ENABLED", "false")
    monkeypatch.setenv("DECNET_VECTORSTORE_TYPE", "sqlite_vec")  # ignored when disabled
    s = get_vectorstore()
    assert isinstance(s, NullVectorStore)


def test_fake_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_VECTORSTORE_ENABLED", "true")
    monkeypatch.setenv("DECNET_VECTORSTORE_TYPE", "fake")
    s = get_vectorstore()
    assert isinstance(s, FakeVectorStore)


def test_sqlite_vec_falls_back_to_fake_when_extension_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The factory must degrade gracefully when sqlite_vec isn't installed:
    log a warning, return FakeVectorStore. Workers stay alive instead of
    crashing on a missing optional dep."""
    monkeypatch.setenv("DECNET_VECTORSTORE_ENABLED", "true")
    monkeypatch.setenv("DECNET_VECTORSTORE_TYPE", "sqlite_vec")
    # Force the import to fail regardless of what's actually installed,
    # so this test is deterministic on dev boxes that have the extension.
    import builtins
    real_import = builtins.__import__

    def _fake_import(name, *a, **kw):  # noqa: ANN001
        if name == "sqlite_vec":
            raise ImportError("forced")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    s = get_vectorstore()
    assert isinstance(s, FakeVectorStore)


def test_unknown_type_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_VECTORSTORE_ENABLED", "true")
    monkeypatch.setenv("DECNET_VECTORSTORE_TYPE", "qdrant")
    with pytest.raises(ValueError, match="Unsupported vectorstore type"):
        get_vectorstore()


def test_default_db_path_honors_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_VECTORSTORE_PATH", "/tmp/explicit.sqlite")
    assert _default_db_path() == "/tmp/explicit.sqlite"


def test_default_db_path_falls_back_to_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DECNET_VECTORSTORE_PATH", raising=False)
    monkeypatch.setattr("os.path.isdir", lambda p: False)
    p = _default_db_path()
    assert p.endswith(".decnet/vectors.sqlite")
    assert p.startswith(os.path.expanduser("~"))
