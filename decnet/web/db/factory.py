"""
Repository factory — selects a :class:`BaseRepository` implementation based on
``DECNET_DB_TYPE`` (``sqlite`` or ``mysql``).
"""
from __future__ import annotations

import os
from typing import Any

from decnet.web.db.repository import BaseRepository


def get_repository(**kwargs: Any) -> BaseRepository:
    """Instantiate the repository implementation selected by ``DECNET_DB_TYPE``.

    Keyword arguments are forwarded to the concrete implementation:

    * SQLite accepts ``db_path``.
    * MySQL accepts ``url`` and engine tuning knobs (``pool_size``, …).
    """
    db_type = os.environ.get("DECNET_DB_TYPE", "sqlite").lower()

    if db_type == "sqlite":
        from decnet.web.db.sqlite.repository import SQLiteRepository
        repo = SQLiteRepository(**kwargs)
    elif db_type == "mysql":
        from decnet.web.db.mysql.repository import MySQLRepository
        repo = MySQLRepository(**kwargs)
    else:
        raise ValueError(f"Unsupported database type: {db_type}")

    from decnet.telemetry import wrap_repository
    return wrap_repository(repo)
