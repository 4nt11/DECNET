from typing import Any
from decnet.env import os
from decnet.web.db.repository import BaseRepository

def get_repository(**kwargs: Any) -> BaseRepository:
    """Factory function to instantiate the correct repository implementation based on environment."""
    db_type = os.environ.get("DECNET_DB_TYPE", "sqlite").lower()

    if db_type == "sqlite":
        from decnet.web.db.sqlite.repository import SQLiteRepository
        return SQLiteRepository(**kwargs)
    elif db_type == "mysql":
        # Placeholder for future implementation
        # from decnet.web.db.mysql.repository import MySQLRepository
        # return MySQLRepository()
        raise NotImplementedError("MySQL support is planned but not yet implemented.")
    else:
        raise ValueError(f"Unsupported database type: {db_type}")
