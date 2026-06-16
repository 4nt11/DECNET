# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLite-backed RPKI result cache.

Schema: ``(ip, asn) -> (rpki_status, rpki_prefix, fetched_at)``.
Key is ``ip`` only — for a given IP the announcing ASN is stable
within the cache TTL, and ASN-change events are rare enough that
letting the entry expire naturally is sufficient.

TTL: 12 hours.  On :func:`open_db` the caller should call
:func:`prune` once to evict stale rows.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Optional, Tuple

TTL_S = 43_200  # 12 hours

_CREATE = """
CREATE TABLE IF NOT EXISTS rpki_cache (
    ip         TEXT    NOT NULL PRIMARY KEY,
    asn        INTEGER NOT NULL,
    rpki_status TEXT   NOT NULL,
    rpki_prefix TEXT,
    fetched_at REAL    NOT NULL
)
"""


def open_db(path: Path) -> sqlite3.Connection:
    """Open (or create) the cache database at *path* and return the connection."""
    con = sqlite3.connect(str(path), check_same_thread=False, timeout=5)
    con.execute(_CREATE)
    con.commit()
    return con


def get(con: sqlite3.Connection, ip: str) -> Optional[Tuple[str, Optional[str]]]:
    """Return ``(rpki_status, rpki_prefix)`` if a fresh entry exists, else ``None``."""
    row = con.execute(
        "SELECT rpki_status, rpki_prefix, fetched_at FROM rpki_cache WHERE ip = ?",
        (ip,),
    ).fetchone()
    if row is None:
        return None
    if time.time() - row[2] > TTL_S:
        return None
    return (row[0], row[1])


def put(
    con: sqlite3.Connection,
    ip: str,
    asn: int,
    status: str,
    prefix: Optional[str],
) -> None:
    """Insert or replace a cache entry."""
    con.execute(
        "INSERT OR REPLACE INTO rpki_cache "
        "(ip, asn, rpki_status, rpki_prefix, fetched_at) VALUES (?, ?, ?, ?, ?)",
        (ip, asn, status, prefix, time.time()),
    )
    con.commit()


def prune(con: sqlite3.Connection) -> int:
    """Delete all entries older than :data:`TTL_S`. Returns the count deleted."""
    cutoff = time.time() - TTL_S
    cur = con.execute("DELETE FROM rpki_cache WHERE fetched_at < ?", (cutoff,))
    con.commit()
    return cur.rowcount
