import aiosqlite
from typing import Any, Optional
from decnet.web.repository import BaseRepository


class SQLiteRepository(BaseRepository):
    """SQLite implementation of the DECNET web repository."""

    def __init__(self, db_path: str = "decnet.db") -> None:
        self.db_path: str = db_path

    async def initialize(self) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            # Logs table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    decky TEXT,
                    service TEXT,
                    event_type TEXT,
                    attacker_ip TEXT,
                    raw_line TEXT
                )
            """)
            # Users table (internal RBAC)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    uuid TEXT PRIMARY KEY,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    role TEXT DEFAULT 'viewer',
                    must_change_password BOOLEAN DEFAULT 0
                )
            """)
            try:
                await db.execute("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0")
            except aiosqlite.OperationalError:
                pass  # Column already exists
            await db.commit()

    async def add_log(self, log_data: dict[str, Any]) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO logs (decky, service, event_type, attacker_ip, raw_line) VALUES (?, ?, ?, ?, ?)",
                (
                    log_data.get("decky"),
                    log_data.get("service"),
                    log_data.get("event_type"),
                    log_data.get("attacker_ip"),
                    log_data.get("raw_line")
                )
            )
            await db.commit()

    async def get_logs(
        self, 
        limit: int = 50, 
        offset: int = 0, 
        search: Optional[str] = None
    ) -> list[dict[str, Any]]:
        query: str = "SELECT * FROM logs"
        params: list[Any] = []
        if search:
            query += " WHERE raw_line LIKE ? OR decky LIKE ? OR service LIKE ? OR attacker_ip LIKE ?"
            like_val = f"%{search}%"
            params.extend([like_val, like_val, like_val, like_val])
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
                
    async def get_total_logs(self, search: Optional[str] = None) -> int:
        query: str = "SELECT COUNT(*) as total FROM logs"
        params: list[Any] = []
        if search:
            query += " WHERE raw_line LIKE ? OR decky LIKE ? OR service LIKE ? OR attacker_ip LIKE ?"
            like_val = f"%{search}%"
            params.extend([like_val, like_val, like_val, like_val])
            
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                row = await cursor.fetchone()
                return row["total"] if row else 0

    async def get_stats_summary(self) -> dict[str, Any]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT COUNT(*) as total_logs FROM logs") as cursor:
                row = await cursor.fetchone()
                total_logs: int = row["total_logs"] if row else 0
            
            async with db.execute("SELECT COUNT(DISTINCT attacker_ip) as unique_attackers FROM logs") as cursor:
                row = await cursor.fetchone()
                unique_attackers: int = row["unique_attackers"] if row else 0

            async with db.execute("SELECT COUNT(DISTINCT decky) as active_deckies FROM logs") as cursor:
                row = await cursor.fetchone()
                active_deckies: int = row["active_deckies"] if row else 0

            return {
                "total_logs": total_logs,
                "unique_attackers": unique_attackers,
                "active_deckies": active_deckies
            }

    async def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM users WHERE username = ?", (username,)) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def get_user_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM users WHERE uuid = ?", (uuid,)) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def create_user(self, user_data: dict[str, Any]) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO users (uuid, username, password_hash, role, must_change_password) VALUES (?, ?, ?, ?, ?)",
                (
                    user_data["uuid"],
                    user_data["username"],
                    user_data["password_hash"],
                    user_data["role"],
                    user_data.get("must_change_password", False)
                )
            )
            await db.commit()

    async def update_user_password(self, uuid: str, password_hash: str, must_change_password: bool = False) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE users SET password_hash = ?, must_change_password = ? WHERE uuid = ?",
                (password_hash, must_change_password, uuid)
            )
            await db.commit()
