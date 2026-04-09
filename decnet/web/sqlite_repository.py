import aiosqlite
from typing import Any, Optional
from decnet.web.repository import BaseRepository
from decnet.config import load_state, _ROOT


class SQLiteRepository(BaseRepository):
    """SQLite implementation of the DECNET web repository."""

    def __init__(self, db_path: str = str(_ROOT / "decnet.db")) -> None:
        self.db_path: str = db_path

    async def initialize(self) -> None:
        """Initialize the database schema synchronously to ensure reliability."""
        import sqlite3
        with sqlite3.connect(self.db_path) as _conn:
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.execute("""
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
            _conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    uuid TEXT PRIMARY KEY,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    role TEXT DEFAULT 'viewer',
                    must_change_password BOOLEAN DEFAULT 0
                )
            """)
            _conn.execute("""
                CREATE TABLE IF NOT EXISTS bounty (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    decky TEXT,
                    service TEXT,
                    attacker_ip TEXT,
                    bounty_type TEXT,
                    payload TEXT
                )
            """)
            _conn.commit()

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

    def _build_where_clause(
        self, 
        search: Optional[str] = None, 
        start_time: Optional[str] = None, 
        end_time: Optional[str] = None,
        base_where: Optional[str] = None,
        base_params: Optional[list[Any]] = None
    ) -> tuple[str, list[Any]]:
        import shlex
        import re
        
        where_clauses = []
        params = []
        
        if base_where:
            where_clauses.append(base_where)
            if base_params:
                params.extend(base_params)
        
        if start_time:
            where_clauses.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            where_clauses.append("timestamp <= ?")
            params.append(end_time)
            
        if search:
            try:
                tokens = shlex.split(search)
            except ValueError:
                tokens = search.split(" ")
                
            core_fields = {
                "decky": "decky",
                "service": "service",
                "event": "event_type",
                "attacker": "attacker_ip",
                "attacker-ip": "attacker_ip",
                "attacker_ip": "attacker_ip"
            }
            
            for token in tokens:
                if ":" in token:
                    key, val = token.split(":", 1)
                    if key in core_fields:
                        where_clauses.append(f"{core_fields[key]} = ?")
                        params.append(val)
                    else:
                        key_safe = re.sub(r'[^a-zA-Z0-9_]', '', key)
                        where_clauses.append(f"json_extract(fields, '$.{key_safe}') = ?")
                        params.append(val)
                else:
                    where_clauses.append("(raw_line LIKE ? OR decky LIKE ? OR service LIKE ? OR attacker_ip LIKE ?)")
                    like_val = f"%{token}%"
                    params.extend([like_val, like_val, like_val, like_val])
                    
        if where_clauses:
            return " WHERE " + " AND ".join(where_clauses), params
        return "", []

    async def get_logs(
        self, 
        limit: int = 50, 
        offset: int = 0, 
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> list[dict[str, Any]]:
        _where, _params = self._build_where_clause(search, start_time, end_time)
        _query = f"SELECT * FROM logs{_where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"  # nosec B608
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

    async def get_logs_after_id(
        self, 
        last_id: int, 
        limit: int = 50, 
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> list[dict[str, Any]]:
        _where, _params = self._build_where_clause(search, start_time, end_time, base_where="id > ?", base_params=[last_id])
        _query = f"SELECT * FROM logs{_where} ORDER BY id ASC LIMIT ?"  # nosec B608
        _params.append(limit)

        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute(_query, _params) as _cursor:
                _rows: list[aiosqlite.Row] = await _cursor.fetchall()
                return [dict(_row) for _row in _rows]

    async def get_total_logs(
        self, 
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> int:
        _where, _params = self._build_where_clause(search, start_time, end_time)
        _query = f"SELECT COUNT(*) as total FROM logs{_where}"  # nosec B608
            
        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute(_query, _params) as _cursor:
                _row: Optional[aiosqlite.Row] = await _cursor.fetchone()
                return _row["total"] if _row else 0

    async def get_log_histogram(
        self,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        interval_minutes: int = 15
    ) -> list[dict[str, Any]]:
        # Map interval to sqlite strftime modifiers
        # Since SQLite doesn't have an easy "bucket by X minutes" natively, 
        # we can do it by grouping by (strftime('%s', timestamp) / (interval_minutes * 60))
        # and then multiplying back to get the bucket start time.
        
        _where, _params = self._build_where_clause(search, start_time, end_time)
        
        _query = f"""
            SELECT 
                datetime((strftime('%s', timestamp) / {interval_minutes * 60}) * {interval_minutes * 60}, 'unixepoch') as bucket_time,
                COUNT(*) as count
            FROM logs
            {_where}
            GROUP BY bucket_time
            ORDER BY bucket_time ASC
        """  # nosec B608
        
        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute(_query, _params) as _cursor:
                _rows: list[aiosqlite.Row] = await _cursor.fetchall()
                return [{"time": _row["bucket_time"], "count": _row["count"]} for _row in _rows]

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

    async def add_bounty(self, bounty_data: dict[str, Any]) -> None:
        import json
        async with aiosqlite.connect(self.db_path) as _db:
            await _db.execute(
                "INSERT INTO bounty (decky, service, attacker_ip, bounty_type, payload) VALUES (?, ?, ?, ?, ?)",
                (
                    bounty_data.get("decky"),
                    bounty_data.get("service"),
                    bounty_data.get("attacker_ip"),
                    bounty_data.get("bounty_type"),
                    json.dumps(bounty_data.get("payload", {}))
                )
            )
            await _db.commit()

    def _build_bounty_where(
        self, 
        bounty_type: Optional[str] = None,
        search: Optional[str] = None
    ) -> tuple[str, list[Any]]:
        _where_clauses = []
        _params = []
        
        if bounty_type:
            _where_clauses.append("bounty_type = ?")
            _params.append(bounty_type)
            
        if search:
            _where_clauses.append("(decky LIKE ? OR service LIKE ? OR attacker_ip LIKE ? OR payload LIKE ?)")
            _like_val = f"%{search}%"
            _params.extend([_like_val, _like_val, _like_val, _like_val])
            
        if _where_clauses:
            return " WHERE " + " AND ".join(_where_clauses), _params
        return "", []

    async def get_bounties(
        self, 
        limit: int = 50, 
        offset: int = 0, 
        bounty_type: Optional[str] = None,
        search: Optional[str] = None
    ) -> list[dict[str, Any]]:
        import json
        _where, _params = self._build_bounty_where(bounty_type, search)
        _query = f"SELECT * FROM bounty{_where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"  # nosec B608
        _params.extend([limit, offset])

        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute(_query, _params) as _cursor:
                _rows: list[aiosqlite.Row] = await _cursor.fetchall()
                _results = []
                for _row in _rows:
                    _d = dict(_row)
                    try:
                        _d["payload"] = json.loads(_d["payload"])
                    except Exception:
                        pass
                    _results.append(_d)
                return _results

    async def get_total_bounties(self, bounty_type: Optional[str] = None, search: Optional[str] = None) -> int:
        _where, _params = self._build_bounty_where(bounty_type, search)
        _query = f"SELECT COUNT(*) as total FROM bounty{_where}"  # nosec B608
            
        async with aiosqlite.connect(self.db_path) as _db:
            _db.row_factory = aiosqlite.Row
            async with _db.execute(_query, _params) as _cursor:
                _row: Optional[aiosqlite.Row] = await _cursor.fetchone()
                return _row["total"] if _row else 0
