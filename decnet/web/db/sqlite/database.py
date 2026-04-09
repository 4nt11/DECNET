from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import create_engine
from sqlmodel import SQLModel
from pathlib import Path

# We need both sync and async engines for SQLite
# Sync for initialization (DDL) and async for standard queries

def get_async_engine(db_path: str):
    # If it's a memory URI, don't add the extra slash that turns it into a relative file
    prefix = "sqlite+aiosqlite:///"
    if db_path.startswith("file:"):
        prefix = "sqlite+aiosqlite:///"
    return create_async_engine(f"{prefix}{db_path}", echo=False, connect_args={"uri": True})

def get_sync_engine(db_path: str):
    prefix = "sqlite:///"
    return create_engine(f"{prefix}{db_path}", echo=False, connect_args={"uri": True})

def init_db(db_path: str):
    """Synchronously create all tables."""
    engine = get_sync_engine(db_path)
    # Ensure WAL mode is set
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
    SQLModel.metadata.create_all(engine)

async def get_session(engine) -> AsyncSession:
    async_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session
