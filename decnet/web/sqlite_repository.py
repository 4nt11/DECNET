import aiosqlite
from typing import Any, Optional
from decnet.web.repository import BaseRepository
from decnet.config import load_state, _ROOT


class SQLiteRepository(BaseRepository):
    """SQLite implementation of the DECNET web repository."""

    def __init__(self, db_path: str = str(_ROOT / "decnet.db")) -> None:
        self.db_path: str = db_path

    async def initialize(self) -> None:
        async with aiosqlite.connect(self.db_path) as _db:
            # Logs table
            await _db.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    decky TEXT,
                    service TEXT,
                    event_type TEXT,
                    attacker_ip TEXT,
                    raw_line TEXT,
                    fields TEXT,
                    msg TEXT
                )
            """)
            try:
                await _db.execute("ALTER TABLE logs ADD COLUMN fields TEXT")
            except aiosqlite.OperationalError:
                pass
            try:
                await _db.execute("ALTER TABLE logs ADD COLUMN msg TEXT")
            except aiosqlite.OperationalError:
                pass
            # Users table (internal RBAC)
            await _db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    uuid TEXT PRIMARY KEY,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    role TEXT DEFAULT 'viewer',
                    must_change_password BOOLEAN DEFAULT 0
                )
            """)
            try:
                await _db.execute("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0")
            except aiosqlite.OperationalError:
                pass  # Column already exists
            await _db.commit()

    async def add_log(self, log_data: dict[str, Any]) -> None:
        async with aiosqlite.connect(self.db_path) as _db:
            _timestamp: Any = log_data.get("timestamp")
            if _timestamp:
                await _db.execute(
                    "INSERT INTO logs (timestamp, decky, service, event_type, attacker_ip, raw_line, fields, msg) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        _timestamp,
                        log_data.get("decky"),
                        log_data.get("service"),
                        log_data.get("event_type"),
                        log_data.get("attacker_ip"),
                        log_data.get("raw_line"),
                        log_data.get("fields"),
                        log_data.get("msg")
                    )
                )
            else:
                await _db.execute(
                    "INSERT INTO logs (decky, service, event_type, attacker_ip, raw_line, fields, msg) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        log_data.get("decky"),
                        log_data.get("service"),
                        log_data.get("event_type"),
                        log_data.get("attacker_ip"),
                        log_data.get("raw_line"),
                        log_data.get("fields"),
                        log_data.get("msg")
                    )
                )
            await _db.commit()

    async def get_logs(
        self, 
        limit: int = 50, 
        offset: int = 0, 
        search: Optional[str] = None
    ) -> list[dict[str, Any]]:
        _query: str = "SELECT * FROM logs"
        _params: list[Any] = []
        if search:
            _query += " WHERE raw_line LIKE ? OR decky LIKE ? OR service LIKE ? OR attacker_ip LIKE ?"
            _like_val: str = f"%{search}%"
            _params.extend([_like_val, _like_val, _like_val, _like_val])
        
        _query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        _params.extend([limit, offset])

        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute(_query, _params) as _cursor:
                _rows: list[aiosqlite.Row] = await _cursor.fetchall()
                return [dict(_row) for _row in _rows]
                
    async def get_max_log_id(self) -> int:
        _query: str = "SELECT MAX(id) as max_id FROM logs"
        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute(_query) as _cursor:
                _row: aiosqlite.Row | None = await _cursor.fetchone()
                return _row["max_id"] if _row and _row["max_id"] is not None else 0

    async def get_logs_after_id(self, last_id: int, limit: int = 50, search: Optional[str] = None) -> list[dict[str, Any]]:
        _query: str = "SELECT * FROM logs WHERE id > ?"
        _params: list[Any] = [last_id]

        if search:
            _query += " AND (raw_line LIKE ? OR decky LIKE ? OR service LIKE ? OR attacker_ip LIKE ?)"
            _like_val: str = f"%{search}%"
            _params.extend([_like_val, _like_val, _like_val, _like_val])

        _query += " ORDER BY id ASC LIMIT ?"
        _params.append(limit)

        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute(_query, _params) as _cursor:
                _rows: list[aiosqlite.Row] = await _cursor.fetchall()
                return [dict(_row) for _row in _rows]

    async def get_total_logs(self, search: Optional[str] = None) -> int:
        _query: str = "SELECT COUNT(*) as total FROM logs"
        _params: list[Any] = []
        if search:
            _query += " WHERE raw_line LIKE ? OR decky LIKE ? OR service LIKE ? OR attacker_ip LIKE ?"
            _like_val: str = f"%{search}%"
            _params.extend([_like_val, _like_val, _like_val, _like_val])
            
        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute(_query, _params) as _cursor:
                _row: Optional[aiosqlite.Row] = await _cursor.fetchone()
                return _row["total"] if _row else 0

    async def get_stats_summary(self) -> dict[str, Any]:
        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute("SELECT COUNT(*) as total_logs FROM logs") as _cursor:
                _row: Optional[aiosqlite.Row] = await _cursor.fetchone()
                _total_logs: int = _row["total_logs"] if _row else 0
            
            async with _db.execute("SELECT COUNT(DISTINCT attacker_ip) as unique_attackers FROM logs") as _cursor:
                _row = await _cursor.fetchone()
                _unique_attackers: int = _row["unique_attackers"] if _row else 0

            # Active deckies are those that HAVE interaction logs
            async with _db.execute("SELECT COUNT(DISTINCT decky) as active_deckies FROM logs") as _cursor:
                _row = await _cursor.fetchone()
                _active_deckies: int = _row["active_deckies"] if _row else 0

            # Deployed deckies are all those in the state file
            _state = load_state()
            _deployed_deckies: int = 0
            if _state:
                _deployed_deckies = len(_state[0].deckies)

            return {
                "total_logs": _total_logs,
                "unique_attackers": _unique_attackers,
                "active_deckies": _active_deckies,
                "deployed_deckies": _deployed_deckies
            }

    async def get_deckies(self) -> list[dict[str, Any]]:
        _state = load_state()
        if not _state:
            return []
        
        # We can also enrich this with interaction counts/last seen from DB
        _deckies: list[dict[str, Any]] = []
        for _d in _state[0].deckies:
            _deckies.append(_d.model_dump())
        
        return _deckies

    async def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute("SELECT * FROM users WHERE username = ?", (username,)) as _cursor:
                _row: Optional[aiosqlite.Row] = await _cursor.fetchone()
                return dict(_row) if _row else None

    async def get_user_by_uuid(self, uuid: str) -> Optional[dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute("SELECT * FROM users WHERE uuid = ?", (uuid,)) as _cursor:
                _row: Optional[aiosqlite.Row] = await _cursor.fetchone()
                return dict(_row) if _row else None

    async def create_user(self, user_data: dict[str, Any]) -> None:
        async with aiosqlite.connect(self.db_path) as _db:
            await _db.execute(
                "INSERT INTO users (uuid, username, password_hash, role, must_change_password) VALUES (?, ?, ?, ?, ?)",
                (
                    user_data["uuid"],
                    user_data["username"],
                    user_data["password_hash"],
                    user_data["role"],
                    user_data.get("must_change_password", False)
                )
            )
            await _db.commit()

    async def update_user_password(self, uuid: str, password_hash: str, must_change_password: bool = False) -> None:
        async with aiosqlite.connect(self.db_path) as _db:
            await _db.execute(
                "UPDATE users SET password_hash = ?, must_change_password = ? WHERE uuid = ?",
                (password_hash, must_change_password, uuid)
            )
            await _db.commit()
