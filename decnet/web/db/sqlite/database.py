import os

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import create_engine, Engine, event
from sqlmodel import SQLModel
from typing import AsyncGenerator

# We need both sync and async engines for SQLite
# Sync for initialization (DDL) and async for standard queries

def get_async_engine(db_path: str) -> AsyncEngine:
    # If it's a memory URI, don't add the extra slash that turns it into a relative file
    prefix = "sqlite+aiosqlite:///"
    if db_path.startswith(":memory:"):
        prefix = "sqlite+aiosqlite://"

    pool_size = int(os.environ.get("DECNET_DB_POOL_SIZE", "20"))
    max_overflow = int(os.environ.get("DECNET_DB_MAX_OVERFLOW", "40"))

    pool_recycle = int(os.environ.get("DECNET_DB_POOL_RECYCLE", "3600"))
    # SQLite is a local file — dead-connection probes are pure overhead.
    # Env var stays for network-mounted setups that still want it.
    pool_pre_ping = os.environ.get("DECNET_DB_POOL_PRE_PING", "false").lower() == "true"

    engine = create_async_engine(
        f"{prefix}{db_path}",
        echo=False,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_recycle=pool_recycle,
        pool_pre_ping=pool_pre_ping,
        connect_args={"uri": True, "timeout": 30},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _conn_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    return engine

def get_sync_engine(db_path: str) -> Engine:
    prefix = "sqlite:///"
    if db_path.startswith(":memory:"):
        prefix = "sqlite://"
    return create_engine(f"{prefix}{db_path}", echo=False, connect_args={"uri": True})

def init_db(db_path: str) -> None:
    """Synchronously create all tables."""
    engine = get_sync_engine(db_path)
    # Ensure WAL mode is set
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
    SQLModel.metadata.create_all(engine)

async def get_session(engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    async_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session
