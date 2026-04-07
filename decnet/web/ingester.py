import asyncio
import os
import logging
from typing import Any
from pathlib import Path

from decnet.correlation.parser import parse_line
from decnet.web.repository import BaseRepository

logger = logging.getLogger("decnet.web.ingester")

async def log_ingestion_worker(repo: BaseRepository) -> None:
    """
    Background task that tails the DECNET_INGEST_LOG_FILE and
    inserts parsed LogEvents into the SQLite repository.
    """
    log_file_path_str = os.environ.get("DECNET_INGEST_LOG_FILE")
    if not log_file_path_str:
        logger.warning("DECNET_INGEST_LOG_FILE not set. Log ingestion disabled.")
        return

    log_path = Path(log_file_path_str)
    position = 0
    
    logger.info(f"Starting log ingestion from {log_path}")

    while True:
        try:
            if not log_path.exists():
                await asyncio.sleep(2)
                continue
                
            stat = log_path.stat()
            if stat.st_size < position:
                # File rotated or truncated
                position = 0
                
            if stat.st_size == position:
                # No new data
                await asyncio.sleep(1)
                continue
                
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(position)
                while True:
                    line = f.readline()
                    if not line:
                        break # EOF reached
                    
                    event = parse_line(line)
                    if event:
                        log_data = {
                            "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                            "decky": event.decky,
                            "service": event.service,
                            "event_type": event.event_type,
                            "attacker_ip": event.attacker_ip or "Unknown",
                            "raw_line": event.raw
                        }
                        await repo.add_log(log_data)
                        
                position = f.tell()
                
        except Exception as e:
            logger.error(f"Error in log ingestion worker: {e}")
            await asyncio.sleep(5)
            
        await asyncio.sleep(1)
