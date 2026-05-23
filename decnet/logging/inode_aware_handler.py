# SPDX-License-Identifier: AGPL-3.0-or-later
"""
RotatingFileHandler that detects external deletion or rotation.

Stdlib ``RotatingFileHandler`` holds an open file descriptor for the
lifetime of the handler.  If the target file is deleted (``rm``) or
rotated out (``logrotate`` without ``copytruncate``), the handler keeps
writing to the now-orphaned inode until its own size-based rotation
finally triggers — silently losing every line in between.

Stdlib ``WatchedFileHandler`` solves exactly this problem but doesn't
rotate by size.  This subclass combines both: before each emit we stat
the configured path and compare its inode/device to the currently open
file; on mismatch we close and reopen.

Cheap: one ``os.stat`` per log record.  Matches the pattern used by
``decnet/collector/worker.py:_reopen_if_needed``.
"""
from __future__ import annotations

import logging
import logging.handlers
import os


class InodeAwareRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """RotatingFileHandler that reopens the target on external rotation/deletion."""

    def _should_reopen(self) -> bool:
        if self.stream is None:
            return True
        try:
            disk_stat = os.stat(self.baseFilename)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        try:
            open_stat = os.fstat(self.stream.fileno())
        except OSError:
            return True
        return (disk_stat.st_ino != open_stat.st_ino
                or disk_stat.st_dev != open_stat.st_dev)

    def emit(self, record: logging.LogRecord) -> None:
        if self._should_reopen():
            try:
                if self.stream is not None:
                    self.close()
            except Exception:  # nosec B110
                pass
            try:
                self.stream = self._open()
            except OSError:
                # A logging handler MUST NOT crash its caller. If we can't
                # reopen (e.g. file is root-owned after `sudo decnet deploy`
                # and the current process is non-root), defer to the stdlib
                # error path, which just prints a traceback to stderr.
                self.handleError(record)
                return
        super().emit(record)
