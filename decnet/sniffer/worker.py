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
import contextlib
import os
import subprocess  # nosec B404 — needed for interface checks
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    make_thread_safe_publisher,
    run_control_listener_signal,
    run_health_heartbeat,
)
from decnet.logging import get_logger
from decnet.network import HOST_IPVLAN_IFACE, HOST_MACVLAN_IFACE
from decnet.sniffer.fingerprint import SnifferEngine
from decnet.sniffer.syslog import write_event
from decnet.telemetry import traced as _traced

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


def _make_decky_traffic_publisher(
    bus: BaseBus,
    loop: asyncio.AbstractEventLoop,
) -> Callable[[str, str, dict[str, Any]], None]:
    """Wrap :func:`make_thread_safe_publisher` with the decky-traffic topic.

    The scapy sniff loop runs in a dedicated worker thread — this adapter
    turns ``(decky_name, event_type, payload)`` calls from the engine into
    a bus publish on ``decky.{name}.traffic`` without blocking the sniff
    thread on the network round-trip.
    """
    raw = make_thread_safe_publisher(bus, loop)

    def _publish(decky_name: str, event_type: str, payload: dict[str, Any]) -> None:
        topic = _topics.decky(decky_name, _topics.DECKY_TRAFFIC)
        raw(topic, payload, event_type)

    return _publish


def _interface_exists(iface: str) -> bool:
    """Check if a network interface exists on this host."""
    try:
        result = subprocess.run(  # nosec B603 B607 — hardcoded args
            ["ip", "link", "show", iface],
            capture_output=True, text=True, check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


@_traced("sniffer.sniff_loop")
def _sniff_loop(
    interface: str,
    log_path: Path,
    json_path: Path,
    stop_event: threading.Event,
    bpf_filter: str = "tcp",
    publish_fn: Callable[[str, str, dict[str, Any]], None] | None = None,
    engine: "SnifferEngine | None" = None,
) -> None:
    """Blocking sniff loop. Runs in a dedicated thread via asyncio.to_thread.

    ``bpf_filter`` selects the traffic to capture.  ``engine`` is shared
    with the caller so the TCP and QUIC loops use the same session state and
    dedup cache.  When ``engine`` is None a fresh one is created.
    """
    try:
        from scapy.sendrecv import sniff
    except ImportError:
        logger.error("scapy not installed — sniffer cannot start")
        return

    if engine is None:
        ip_map = _load_ip_to_decky()
        if not ip_map:
            logger.warning("sniffer: no deckies in state — nothing to sniff")
            return

        def _write_fn(line: str) -> None:
            write_event(line, log_path, json_path)

        engine = SnifferEngine(
            ip_to_decky=ip_map, write_fn=_write_fn, publish_fn=publish_fn,
        )

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

        threading.Thread(target=_refresh_loop, daemon=True).start()

    pkt_fn = engine.on_quic_packet if bpf_filter.startswith("udp") else engine.on_packet
    logger.info(
        "sniffer: sniffing on interface=%s filter=%r deckies=%d",
        interface, bpf_filter, len(engine._ip_to_decky),
    )

    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=pkt_fn,
            store=False,
            stop_filter=lambda pkt: stop_event.is_set(),
        )
    except Exception as exc:
        logger.error("sniffer: scapy sniff exited (filter=%r): %s", bpf_filter, exc)
    finally:
        stop_event.set()
        logger.info("sniffer: sniff loop ended (filter=%r)", bpf_filter)


@_traced("sniffer.worker")
async def sniffer_worker(log_file: str) -> None:
    """
    Async entry point — started as asyncio.create_task in the API lifespan.

    Fully fault-isolated: catches all exceptions, logs them, and returns
    cleanly. The API continues running regardless of sniffer state.
    """
    try:
        # Interface selection: explicit env override wins, otherwise probe
        # both the MACVLAN and IPvlan host-side names since the driver
        # choice is per-deploy (--ipvlan flag).
        env_iface = os.environ.get("DECNET_SNIFFER_IFACE")
        if env_iface:
            interface = env_iface
        elif _interface_exists(HOST_MACVLAN_IFACE):
            interface = HOST_MACVLAN_IFACE
        elif _interface_exists(HOST_IPVLAN_IFACE):
            interface = HOST_IPVLAN_IFACE
        else:
            logger.warning(
                "sniffer: neither %s nor %s found — sniffer disabled "
                "(fleet may not be deployed yet)",
                HOST_MACVLAN_IFACE, HOST_IPVLAN_IFACE,
            )
            return

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

        loop = asyncio.get_running_loop()

        # Connect to the bus for decky.{id}.traffic fan-out.  Failure here
        # is non-fatal: the sniffer still writes syslog, it just doesn't
        # push notifications to downstream consumers.
        bus: BaseBus | None = None
        try:
            candidate = get_bus(client_name="sniffer")
            await candidate.connect()
            bus = candidate
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "sniffer: bus unavailable, running in publish-off mode: %s", exc,
            )

        publish_fn: Callable[[str, str, dict[str, Any]], None] | None = None
        if bus is not None:
            publish_fn = _make_decky_traffic_publisher(bus, loop)

        # Workers panel: heartbeat + SIGTERM-based stop control.  The
        # sniff loop is a blocking scapy thread, so an asyncio shutdown
        # event can't reach it — translating the bus stop into SIGTERM
        # routes through the existing CancelledError path below.
        heartbeat_task = asyncio.create_task(run_health_heartbeat(bus, "sniffer"))
        control_task = asyncio.create_task(
            run_control_listener_signal(bus, "sniffer"),
        )

        # Build a shared engine so both sniff threads (TCP + UDP/443) share
        # the same session state, dedup cache, and IP map.
        ip_map = _load_ip_to_decky()
        if not ip_map:
            logger.warning(
                "sniffer: no deckies in state — sniffer disabled",
            )
            return

        def _write_fn(line: str) -> None:
            from decnet.sniffer.syslog import write_event as _we
            _we(line, log_path, json_path)

        shared_engine = SnifferEngine(
            ip_to_decky=ip_map, write_fn=_write_fn, publish_fn=publish_fn,
        )

        def _refresh_loop() -> None:
            while not stop_event.is_set():
                stop_event.wait(_IP_MAP_REFRESH_INTERVAL)
                if stop_event.is_set():
                    break
                try:
                    new_map = _load_ip_to_decky()
                    if new_map:
                        shared_engine.update_ip_map(new_map)
                except Exception as exc:
                    logger.debug("sniffer: ip map refresh failed: %s", exc)

        threading.Thread(target=_refresh_loop, daemon=True, name="sniffer-ipmap").start()

        # Dedicated thread pool: 2 workers = TCP loop + UDP/443 QUIC loop.
        sniffer_pool = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="decnet-sniffer",
        )

        try:
            tcp_future = loop.run_in_executor(
                sniffer_pool, _sniff_loop,
                interface, log_path, json_path, stop_event, "tcp", publish_fn, shared_engine,
            )
            quic_future = loop.run_in_executor(
                sniffer_pool, _sniff_loop,
                interface, log_path, json_path, stop_event,
                "udp port 443", publish_fn, shared_engine,
            )
            await asyncio.gather(tcp_future, quic_future)
        except asyncio.CancelledError:
            logger.info("sniffer: shutdown requested")
            stop_event.set()
            sniffer_pool.shutdown(wait=False)
            raise
        finally:
            sniffer_pool.shutdown(wait=False)
            for t in (heartbeat_task, control_task):
                t.cancel()
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await t
            if bus is not None:
                with contextlib.suppress(Exception):
                    await bus.close()

    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("sniffer: worker failed — API continues without sniffing: %s", exc)
