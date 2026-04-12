import asyncio
import os
import logging
import json
from typing import Any
from pathlib import Path

from decnet.web.db.repository import BaseRepository

logger: logging.Logger = logging.getLogger("decnet.web.ingester")

async def log_ingestion_worker(repo: BaseRepository) -> None:
    """
    Background task that tails the DECNET_INGEST_LOG_FILE.json and
    inserts structured JSON logs into the SQLite repository.
    """
    _base_log_file: str | None = os.environ.get("DECNET_INGEST_LOG_FILE")
    if not _base_log_file:
        logger.warning("DECNET_INGEST_LOG_FILE not set. Log ingestion disabled.")
        return

    _json_log_path: Path = Path(_base_log_file).with_suffix(".json")
    _position: int = 0
    
    logger.info(f"Starting JSON log ingestion from {_json_log_path}")

    while True:
        try:
            if not _json_log_path.exists():
                await asyncio.sleep(2)
                continue
                
            _stat: os.stat_result = _json_log_path.stat()
            if _stat.st_size < _position:
                # File rotated or truncated
                _position = 0
                
            if _stat.st_size == _position:
                # No new data
                await asyncio.sleep(1)
                continue
                
            with open(_json_log_path, "r", encoding="utf-8", errors="replace") as _f:
                _f.seek(_position)
                while True:
                    _line: str = _f.readline()
                    if not _line:
                        break # EOF reached
                    
                    if not _line.endswith('\n'):
                        # Partial line read, don't process yet, don't advance position
                        break

                    try:
                        _log_data: dict[str, Any] = json.loads(_line.strip())
                        await repo.add_log(_log_data)
                        await _extract_bounty(repo, _log_data)
                    except json.JSONDecodeError:
                        logger.error(f"Failed to decode JSON log line: {_line}")
                        continue
                    
                    # Update position after successful line read
                    _position = _f.tell()
                
        except Exception as _e:
            logger.error(f"Error in log ingestion worker: {_e}")
            await asyncio.sleep(5)
            
        await asyncio.sleep(1)


async def _extract_bounty(repo: BaseRepository, log_data: dict[str, Any]) -> None:
    """Detect and extract valuable artifacts (bounties) from log entries."""
    _fields = log_data.get("fields")
    if not isinstance(_fields, dict):
        return

    # 1. Credentials (User/Pass)
    _user = _fields.get("username")
    _pass = _fields.get("password")
    
    if _user and _pass:
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": log_data.get("service"),
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "credential",
            "payload": {
                "username": _user,
                "password": _pass
            }
        })
    
    # 2. Add more extractors here later (e.g. file hashes, crypto keys)
