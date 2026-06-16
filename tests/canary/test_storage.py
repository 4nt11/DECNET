# SPDX-License-Identifier: AGPL-3.0-or-later
"""Coverage for the on-disk blob store."""
from __future__ import annotations

import hashlib

from decnet.canary import storage


def test_write_blob_is_idempotent(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DECNET_CANARY_BLOB_DIR", str(tmp_path))
    sha1, p1, sz1 = storage.write_blob(b"hello canary")
    sha2, p2, sz2 = storage.write_blob(b"hello canary")
    assert sha1 == sha2 == hashlib.sha256(b"hello canary").hexdigest()
    assert p1 == p2
    assert sz1 == sz2 == len(b"hello canary")
    # Two-level fan-out: ab/cd/abcd...
    assert p1.parent.parent.parent == tmp_path
    assert p1.parent.name == sha1[2:4]
    assert p1.parent.parent.name == sha1[:2]


def test_read_blob_returns_bytes(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DECNET_CANARY_BLOB_DIR", str(tmp_path))
    sha, _, _ = storage.write_blob(b"some payload")
    assert storage.read_blob(sha) == b"some payload"


def test_unlink_blob_returns_false_for_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DECNET_CANARY_BLOB_DIR", str(tmp_path))
    sha = "0" * 64
    assert storage.unlink_blob(sha) is False


def test_unlink_blob_removes_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DECNET_CANARY_BLOB_DIR", str(tmp_path))
    sha, path, _ = storage.write_blob(b"to be removed")
    assert path.exists()
    assert storage.unlink_blob(sha) is True
    assert not path.exists()
    # Second unlink is a no-op rather than a crash.
    assert storage.unlink_blob(sha) is False


def test_blob_dir_honors_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DECNET_CANARY_BLOB_DIR", str(tmp_path / "alt"))
    assert storage.blob_dir() == tmp_path / "alt"


def test_short_sha_rejected() -> None:
    import pytest
    with pytest.raises(ValueError):
        storage._path_for("abc")
