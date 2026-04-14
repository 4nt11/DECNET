"""
Fleet-wide MACVLAN sniffer worker.

Runs as a single host-side async background task that sniffs all TLS
traffic on the MACVLAN host interface. Maps packets to deckies by IP
and feeds fingerprint events into the existing log pipeline.

Modeled on decnet.collector.worker — same lifecycle pattern.
Fault-isolated: any exception is logged and the worker exits cleanly.
The API never depends on this worker being alive.
"""

import asyncio
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from decnet.logging import get_logger
from decnet.network import HOST_MACVLAN_IFACE
from decnet.sniffer.fingerprint import SnifferEngine
from decnet.sniffer.syslog import write_event

logger = get_logger("sniffer")

_IP_MAP_REFRESH_INTERVAL: float = 60.0


def _load_ip_to_decky() -> dict[str, str]:
    """Build IP → decky-name mapping from decnet-state.json."""
    from decnet.config import load_state
    state = load_state()
    if state is None:
        return {}
    config, _ = state
    mapping: dict[str, str] = {}
    for decky in config.deckies:
        mapping[decky.ip] = decky.name
    return mapping


def _interface_exists(iface: str) -> bool:
    """Check if a network interface exists on this host."""
    try:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True, check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def _sniff_loop(
    interface: str,
    log_path: Path,
    json_path: Path,
    stop_event: threading.Event,
) -> None:
    """Blocking sniff loop. Runs in a dedicated thread via asyncio.to_thread."""
    try:
        from scapy.sendrecv import sniff
    except ImportError:
        logger.error("scapy not installed — sniffer cannot start")
        return

    ip_map = _load_ip_to_decky()
    if not ip_map:
        logger.warning("sniffer: no deckies in state — nothing to sniff")
        return

    def _write_fn(line: str) -> None:
        write_event(line, log_path, json_path)

    engine = SnifferEngine(ip_to_decky=ip_map, write_fn=_write_fn)

    # Periodically refresh IP map in a background daemon thread
    def _refresh_loop() -> None:
        while not stop_event.is_set():
            stop_event.wait(_IP_MAP_REFRESH_INTERVAL)
            if stop_event.is_set():
                break
            try:
                new_map = _load_ip_to_decky()
                if new_map:
                    engine.update_ip_map(new_map)
            except Exception as exc:
                logger.debug("sniffer: ip map refresh failed: %s", exc)

    refresh_thread = threading.Thread(target=_refresh_loop, daemon=True)
    refresh_thread.start()

    logger.info("sniffer: sniffing on interface=%s deckies=%d", interface, len(ip_map))

    try:
        sniff(
            iface=interface,
            filter="tcp",
            prn=engine.on_packet,
            store=False,
            stop_filter=lambda pkt: stop_event.is_set(),
        )
    except Exception as exc:
        logger.error("sniffer: scapy sniff exited: %s", exc)
    finally:
        stop_event.set()
        logger.info("sniffer: sniff loop ended")


async def sniffer_worker(log_file: str) -> None:
    """
    Async entry point — started as asyncio.create_task in the API lifespan.

    Fully fault-isolated: catches all exceptions, logs them, and returns
    cleanly. The API continues running regardless of sniffer state.
    """
    try:
        interface = os.environ.get("DECNET_SNIFFER_IFACE", HOST_MACVLAN_IFACE)

        if not _interface_exists(interface):
            logger.warning(
                "sniffer: interface %s not found — sniffer disabled "
                "(fleet may not be deployed yet)", interface,
            )
            return

        log_path = Path(log_file)
        json_path = log_path.with_suffix(".json")
        log_path.parent.mkdir(parents=True, exist_ok=True)

        stop_event = threading.Event()

        try:
            await asyncio.to_thread(_sniff_loop, interface, log_path, json_path, stop_event)
        except asyncio.CancelledError:
            logger.info("sniffer: shutdown requested")
            stop_event.set()
            raise

    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("sniffer: worker failed — API continues without sniffing: %s", exc)
