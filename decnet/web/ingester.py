import asyncio
import os
import logging
import json
from typing import Any
from pathlib import Path

from decnet.web.repository import BaseRepository

logger = logging.getLogger("decnet.web.ingester")

async def log_ingestion_worker(repo: BaseRepository) -> None:
    """
    Background task that tails the DECNET_INGEST_LOG_FILE.json and
    inserts structured JSON logs into the SQLite repository.
    """
    base_log_file = os.environ.get("DECNET_INGEST_LOG_FILE")
    if not base_log_file:
        logger.warning("DECNET_INGEST_LOG_FILE not set. Log ingestion disabled.")
        return

    json_log_path = Path(base_log_file).with_suffix(".json")
    position = 0
    
    logger.info(f"Starting JSON log ingestion from {json_log_path}")

    while True:
        try:
            if not json_log_path.exists():
                await asyncio.sleep(2)
                continue
                
            stat = json_log_path.stat()
            if stat.st_size < position:
                # File rotated or truncated
                position = 0
                
            if stat.st_size == position:
                # No new data
                await asyncio.sleep(1)
                continue
                
            with open(json_log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(position)
                while True:
                    line = f.readline()
                    if not line:
                        break # EOF reached
                    
                    if not line.endswith('\n'):
                        # Partial line read, don't process yet, don't advance position
                        break

                    try:
                        log_data = json.loads(line.strip())
                        await repo.add_log(log_data)
                    except json.JSONDecodeError:
                        logger.error(f"Failed to decode JSON log line: {line}")
                        continue
                    
                    # Update position after successful line read
                    position = f.tell()
                
        except Exception as e:
            logger.error(f"Error in log ingestion worker: {e}")
            await asyncio.sleep(5)
            
        await asyncio.sleep(1)
