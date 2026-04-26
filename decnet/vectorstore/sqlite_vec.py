"""SQLite + sqlite-vec backend.

Lazy-imports the ``sqlite_vec`` extension. If the extension isn't
available (the package isn't installed, or the host's libsqlite3 is too
old to load loadable extensions), construction raises
:class:`SqliteVecUnavailable`; the factory catches that and falls back
to :class:`~decnet.vectorstore.fake.FakeVectorStore` with a warning.

Schema:

    CREATE TABLE vectors (
        kind TEXT NOT NULL,
        id   TEXT NOT NULL,
        extractor_version INTEGER NOT NULL DEFAULT 1,
        dim  INTEGER NOT NULL,
        PRIMARY KEY (kind, id)
    );
    CREATE VIRTUAL TABLE vec_<kind> USING vec0(
        embedding float[<dim>]
    );

A vec0 virtual table is created lazily per-kind on first insert
(distinct ``kind`` values get distinct vec0 tables because vec0's dim
is a schema-time constant). The ``vectors`` row is the source of truth
for metadata (extractor_version, dim) and for the (kind, id) → rowid
mapping; vec0 stores only the embedding, keyed by an INTEGER rowid.
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Optional, Sequence

from decnet.vectorstore.base import BaseVectorStore, Neighbor, VectorRecord

LOG = logging.getLogger(__name__)


class SqliteVecUnavailable(RuntimeError):
    """sqlite_vec couldn't be loaded (extension missing / too-old sqlite3)."""


def _load_sqlite_vec(conn: sqlite3.Connection) -> None:
    try:
        import sqlite_vec  # type: ignore[import-untyped]
    except ImportError as e:
        raise SqliteVecUnavailable("sqlite_vec package not installed") from e
    try:
        conn.enable_load_extension(True)
    except (AttributeError, sqlite3.NotSupportedError) as e:
        raise SqliteVecUnavailable(
            "system sqlite3 was built without loadable-extension support"
        ) from e
    try:
        sqlite_vec.load(conn)
    except sqlite3.OperationalError as e:
        raise SqliteVecUnavailable(f"sqlite_vec load failed: {e}") from e
    finally:
        try:
            conn.enable_load_extension(False)
        except sqlite3.NotSupportedError:
            pass


class SqliteVecVectorStore(BaseVectorStore):
    """sqlite-vec backed vector store. Single-file, async-friendly via
    :func:`asyncio.to_thread`. Keep one instance per process.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        # {kind: dim} cached after first insert/probe.
        self._kinds: dict[str, int] = {}

    async def initialize(self) -> None:
        await asyncio.to_thread(self._init_sync)

    def _init_sync(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        _load_sqlite_vec(conn)  # raises SqliteVecUnavailable on failure
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vectors (
                kind TEXT NOT NULL,
                id   TEXT NOT NULL,
                extractor_version INTEGER NOT NULL DEFAULT 1,
                dim  INTEGER NOT NULL,
                rowid_in_vec INTEGER NOT NULL,
                PRIMARY KEY (kind, id)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_vectors_kind ON vectors(kind)"
        )
        conn.commit()
        # Re-hydrate kind→dim cache from any existing rows so a process
        # restart doesn't accept a mismatched dim on the first insert.
        for row in conn.execute("SELECT kind, dim FROM vectors GROUP BY kind"):
            self._kinds[row[0]] = int(row[1])
        self._conn = conn

    async def close(self) -> None:
        await asyncio.to_thread(self._close_sync)

    def _close_sync(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    async def health(self) -> dict:
        return await asyncio.to_thread(self._health_sync)

    def _health_sync(self) -> dict:
        if self._conn is None:
            return {"ok": False, "backend": "sqlite_vec", "reason": "not initialized"}
        try:
            row = self._conn.execute("SELECT COUNT(*) FROM vectors").fetchone()
            return {
                "ok": True,
                "backend": "sqlite_vec",
                "kinds": len(self._kinds),
                "vectors": int(row[0]) if row else 0,
            }
        except sqlite3.Error as e:
            return {"ok": False, "backend": "sqlite_vec", "reason": str(e)}

    @staticmethod
    def _vec_table(kind: str) -> str:
        # Validate the kind so it can't break out of the table name.
        # Allowed: ascii letters, digits, underscore. Anything else =
        # programmer error; raise loudly.
        if not kind or not all(c.isalnum() or c == "_" for c in kind):
            raise ValueError(f"invalid kind {kind!r}: ascii [a-z0-9_] only")
        return f"vec_{kind}"

    def _ensure_kind_table(self, kind: str, dim: int) -> None:
        assert self._conn is not None  # nosec B101
        existing = self._kinds.get(kind)
        if existing is None:
            # vec_<kind> identifier is validated by _vec_table() to be
            # ascii [a-z0-9_] only, and dim is int-cast — no injection
            # vector. The f-string is the only way to interpolate a
            # virtual-table name; placeholders aren't allowed for DDL.
            ddl = (  # nosec B608
                f"CREATE VIRTUAL TABLE IF NOT EXISTS {self._vec_table(kind)} "
                f"USING vec0(embedding float[{int(dim)}])"
            )
            self._conn.execute(ddl)
            self._conn.commit()
            self._kinds[kind] = dim
        elif existing != dim:
            raise ValueError(
                f"vector dim mismatch for kind={kind!r}: "
                f"expected {existing}, got {dim}"
            )

    async def insert(
        self, kind: str, id: str, vector: Sequence[float],
        *, extractor_version: int = 1,
    ) -> None:
        await asyncio.to_thread(
            self._insert_sync, kind, id, list(vector), int(extractor_version)
        )

    def _insert_sync(
        self, kind: str, id: str, vector: list[float], extractor_version: int,
    ) -> None:
        with self._lock:
            assert self._conn is not None  # nosec B101
            dim = len(vector)
            self._ensure_kind_table(kind, dim)
            vec_table = self._vec_table(kind)
            cur = self._conn.cursor()
            existing = cur.execute(
                "SELECT rowid_in_vec FROM vectors WHERE kind=? AND id=?",
                (kind, id),
            ).fetchone()
            if existing is not None:
                rowid = int(existing[0])
                # vec_table is validated; rowid is bound. Safe.
                cur.execute(f"DELETE FROM {vec_table} WHERE rowid=?", (rowid,))  # nosec B608
            import struct
            blob = struct.pack(f"{dim}f", *vector)
            cur.execute(f"INSERT INTO {vec_table}(embedding) VALUES (?)", (blob,))  # nosec B608
            new_rowid = cur.lastrowid
            cur.execute(
                "INSERT OR REPLACE INTO vectors"
                "(kind, id, extractor_version, dim, rowid_in_vec) "
                "VALUES (?, ?, ?, ?, ?)",
                (kind, id, extractor_version, dim, new_rowid),
            )
            self._conn.commit()

    async def get(self, kind: str, id: str) -> Optional[VectorRecord]:
        return await asyncio.to_thread(self._get_sync, kind, id)

    def _get_sync(self, kind: str, id: str) -> Optional[VectorRecord]:
        with self._lock:
            assert self._conn is not None  # nosec B101
            row = self._conn.execute(
                "SELECT extractor_version, dim, rowid_in_vec "
                "FROM vectors WHERE kind=? AND id=?",
                (kind, id),
            ).fetchone()
            if row is None:
                return None
            ext_v, dim, rowid = int(row[0]), int(row[1]), int(row[2])
            vec_table = self._vec_table(kind)
            blob_row = self._conn.execute(f"SELECT embedding FROM {vec_table} WHERE rowid=?", (rowid,)).fetchone()  # nosec B608
            if blob_row is None:
                return None
            import struct
            vec = list(struct.unpack(f"{dim}f", blob_row[0]))
            return VectorRecord(
                kind=kind, id=id, vector=vec, dim=dim,
                extractor_version=ext_v,
            )

    async def delete(self, kind: str, id: str) -> bool:
        return await asyncio.to_thread(self._delete_sync, kind, id)

    def _delete_sync(self, kind: str, id: str) -> bool:
        with self._lock:
            assert self._conn is not None  # nosec B101
            row = self._conn.execute(
                "SELECT rowid_in_vec FROM vectors WHERE kind=? AND id=?",
                (kind, id),
            ).fetchone()
            if row is None:
                return False
            rowid = int(row[0])
            vec_table = self._vec_table(kind)
            self._conn.execute(f"DELETE FROM {vec_table} WHERE rowid=?", (rowid,))  # nosec B608
            self._conn.execute(
                "DELETE FROM vectors WHERE kind=? AND id=?", (kind, id)
            )
            self._conn.commit()
            return True

    async def knn(
        self, kind: str, vector: Sequence[float], k: int = 10,
    ) -> list[Neighbor]:
        return await asyncio.to_thread(self._knn_sync, kind, list(vector), int(k))

    def _knn_sync(self, kind: str, vector: list[float], k: int) -> list[Neighbor]:
        with self._lock:
            assert self._conn is not None  # nosec B101
            existing_dim = self._kinds.get(kind)
            if existing_dim is None:
                return []
            if len(vector) != existing_dim:
                raise ValueError(
                    f"query dim {len(vector)} != stored dim {existing_dim} "
                    f"for kind={kind!r}"
                )
            vec_table = self._vec_table(kind)
            import struct
            qblob = struct.pack(f"{existing_dim}f", *vector)
            knn_sql = f"SELECT rowid, distance FROM {vec_table} WHERE embedding MATCH ? ORDER BY distance LIMIT ?"  # nosec B608
            rows = self._conn.execute(knn_sql, (qblob, max(0, k))).fetchall()
            if not rows:
                return []
            id_map = {
                int(r[0]): r[1]
                for r in self._conn.execute(
                    "SELECT rowid_in_vec, id FROM vectors WHERE kind=?",
                    (kind,),
                )
            }
            out: list[Neighbor] = []
            for rowid, dist in rows:
                rid = id_map.get(int(rowid))
                if rid is None:
                    continue
                out.append(Neighbor(kind=kind, id=rid, distance=float(dist)))
            return out
