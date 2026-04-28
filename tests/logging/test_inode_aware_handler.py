"""
Tests for InodeAwareRotatingFileHandler.

Simulates the two scenarios that break plain RotatingFileHandler:
    1. External `rm` of the log file
    2. External rename (logrotate-style rotation)

In both cases, the next log record must end up in a recreated file on
disk, not the orphaned inode held by the old file descriptor.
"""
import logging
import os

import pytest

from decnet.logging.inode_aware_handler import InodeAwareRotatingFileHandler


def _make_handler(path) -> logging.Handler:
    h = InodeAwareRotatingFileHandler(str(path), maxBytes=10_000_000, backupCount=1)
    h.setFormatter(logging.Formatter("%(message)s"))
    return h


def _record(msg: str) -> logging.LogRecord:
    return logging.LogRecord("t", logging.INFO, __file__, 1, msg, None, None)


def test_writes_land_in_file(tmp_path):
    path = tmp_path / "app.log"
    h = _make_handler(path)
    h.emit(_record("hello"))
    h.close()
    assert path.read_text().strip() == "hello"


def test_reopens_after_unlink(tmp_path):
    path = tmp_path / "app.log"
    h = _make_handler(path)
    h.emit(_record("first"))
    os.remove(path)  # simulate `rm decnet.system.log`
    assert not path.exists()

    h.emit(_record("second"))
    h.close()

    assert path.exists()
    assert path.read_text().strip() == "second"


def test_reopens_after_rename(tmp_path):
    """logrotate rename-and-create: the old path is renamed, then we expect
    writes to go to a freshly created file at the original path."""
    path = tmp_path / "app.log"
    h = _make_handler(path)
    h.emit(_record("pre-rotation"))

    rotated = tmp_path / "app.log.1"
    os.rename(path, rotated)  # simulate logrotate move

    h.emit(_record("post-rotation"))
    h.close()

    assert rotated.read_text().strip() == "pre-rotation"
    assert path.read_text().strip() == "post-rotation"


def test_no_reopen_when_file_is_stable(tmp_path, monkeypatch):
    """Ensure we don't thrash: back-to-back emits must share one FD."""
    path = tmp_path / "app.log"
    h = _make_handler(path)
    h.emit(_record("one"))
    fd_before = h.stream.fileno()
    h.emit(_record("two"))
    fd_after = h.stream.fileno()
    assert fd_before == fd_after
    h.close()
    assert path.read_text().splitlines() == ["one", "two"]


def test_emit_does_not_raise_when_reopen_fails(tmp_path, monkeypatch):
    """A failed reopen must not propagate — it would crash the caller
    (observed in the collector worker when decnet.system.log was root-owned
    and the collector ran non-root)."""
    path = tmp_path / "app.log"
    h = _make_handler(path)
    h.emit(_record("first"))
    os.remove(path)  # force reopen on next emit

    def boom(*_a, **_kw):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(h, "_open", boom)

    # Swallow the stderr traceback stdlib prints via handleError.
    monkeypatch.setattr(h, "handleError", lambda _r: None)

    # Must not raise.
    h.emit(_record("second"))


def test_rotation_by_size_still_works(tmp_path):
    """maxBytes-triggered rotation must still function on top of the inode check."""
    path = tmp_path / "app.log"
    h = InodeAwareRotatingFileHandler(str(path), maxBytes=50, backupCount=1)
    h.setFormatter(logging.Formatter("%(message)s"))
    for i in range(20):
        h.emit(_record(f"line-{i:03d}-xxxxxxxxxxxxxxx"))
    h.close()

    assert path.exists()
    assert (tmp_path / "app.log.1").exists()
