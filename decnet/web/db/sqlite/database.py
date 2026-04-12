from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import create_engine, Engine
from sqlmodel import SQLModel
from typing import AsyncGenerator

# We need both sync and async engines for SQLite
# Sync for initialization (DDL) and async for standard queries

def get_async_engine(db_path: str) -> AsyncEngine:
    # If it's a memory URI, don't add the extra slash that turns it into a relative file
    prefix = "sqlite+aiosqlite:///"
    if db_path.startswith(":memory:"):
        prefix = "sqlite+aiosqlite://"
    return create_async_engine(f"{prefix}{db_path}", echo=False, connect_args={"uri": True})

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
