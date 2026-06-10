# SPDX-License-Identifier: AGPL-3.0-or-later
"""Worker-side syslog-over-TLS forwarder (RFC 5425).

Runs alongside the worker agent. Tails the worker's local RFC 5424 log
file (written by the existing docker-collector) and ships each line to
the master's listener on TCP 6514 using octet-counted framing over mTLS.
Persists the last-forwarded byte offset in a tiny local SQLite so a
master crash never causes loss or duplication.

Design constraints (from the plan, non-negotiable):
* transport MUST be TLS — plaintext syslog is never acceptable between
  hosts; only loopback (decky → worker-local collector) may be plaintext;
* mTLS — the listener pins the worker cert against the DECNET CA, so only
  enrolled workers can push logs;
* offset persistence MUST be transactional w.r.t. the send — we only
  advance the offset after ``writer.drain()`` returns without error.

The forwarder is intentionally a standalone coroutine, not a worker
inside the agent process.  That keeps ``decnet agent`` crashes from
losing the log tail, and vice versa.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import pathlib
import sqlite3
import ssl
from dataclasses import dataclass
from typing import Optional

from decnet.bus.factory import get_bus
from decnet.bus.publish import run_health_heartbeat
from decnet.logging import get_logger
from decnet.swarm import pki

log = get_logger("swarm.forwarder")

# RFC 5425 framing: "<octet-count> <syslog-msg>".
# The message itself is a standard RFC 5424 line (no trailing newline).
_FRAME_SEP = b" "

_INITIAL_BACKOFF = 1.0
_MAX_BACKOFF = 30.0


@dataclass(frozen=True)
class ForwarderConfig:
    log_path: pathlib.Path      # worker's RFC 5424 .log file
    master_host: str
    master_port: int = 6514
    agent_dir: pathlib.Path = pki.DEFAULT_AGENT_DIR
    state_db: Optional[pathlib.Path] = None  # default: agent_dir / "forwarder.db"
    # Max unacked bytes to keep in the local buffer when master is down.
    # We bound the lag to avoid unbounded disk growth on catastrophic master
    # outage — older lines are surfaced as a warning and dropped by advancing
    # the offset.
    max_lag_bytes: int = 128 * 1024 * 1024  # 128 MiB


# ------------------------------------------------------------ offset storage


class _OffsetStore:
    """Single-row SQLite offset tracker. Stdlib only — no ORM, no async."""

    def __init__(self, db_path: pathlib.Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS forwarder_offset ("
            " key TEXT PRIMARY KEY, offset INTEGER NOT NULL)"
        )
        self._conn.commit()

    def get(self, key: str = "default") -> int:
        row = self._conn.execute(
            "SELECT offset FROM forwarder_offset WHERE key=?", (key,)
        ).fetchone()
        return int(row[0]) if row else 0

    def set(self, offset: int, key: str = "default") -> None:
        self._conn.execute(
            "INSERT INTO forwarder_offset(key, offset) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET offset=excluded.offset",
            (key, offset),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------- TLS setup


def build_worker_ssl_context(agent_dir: pathlib.Path) -> ssl.SSLContext:
    """Client-side mTLS context for the forwarder.

    Worker presents its agent bundle (same cert used for the control-plane
    HTTPS listener).  The CA is the DECNET CA; we pin by CA, not hostname,
    because workers reach masters by operator-supplied address.
    """
    bundle = pki.load_worker_bundle(agent_dir)
    if bundle is None:
        raise RuntimeError(
            f"no worker bundle at {agent_dir} — enroll from the master first"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(
        certfile=str(agent_dir / "worker.crt"),
        keyfile=str(agent_dir / "worker.key"),
    )
    ctx.load_verify_locations(cafile=str(agent_dir / "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False
    return ctx


# ----------------------------------------------------------- frame encoding


def encode_frame(line: str) -> bytes:
    """RFC 5425 octet-counted framing: ``"<N> <msg>"``.

    ``N`` is the byte length of the payload that follows (after the space).
    """
    payload = line.rstrip("\n").encode("utf-8", errors="replace")
    return f"{len(payload)}".encode("ascii") + _FRAME_SEP + payload


async def read_frame(reader: asyncio.StreamReader) -> Optional[bytes]:
    """Read one octet-counted frame. Returns None on clean EOF."""
    # Read the ASCII length up to the first space. Bound the prefix so a
    # malicious peer can't force us to buffer unbounded bytes before we know
    # it's a valid frame.
    prefix = b""
    while True:
        c = await reader.read(1)
        if not c:
            return None if not prefix else b""
        if c == _FRAME_SEP:
            break
        if len(prefix) >= 10 or not c.isdigit():
            # RFC 5425 caps the length prefix at ~10 digits (< 4 GiB payload).
            raise ValueError(f"invalid octet-count prefix: {prefix!r}")
        prefix += c
    n = int(prefix)
    buf = await reader.readexactly(n)
    return buf


# ----------------------------------------------------------------- main loop


async def _send_batch(
    writer: asyncio.StreamWriter,
    offset: int,
    lines: list[tuple[int, str]],
    store: _OffsetStore,
) -> int:
    """Write every line as a frame, drain, then persist the last offset."""
    for _, line in lines:
        writer.write(encode_frame(line))
    await writer.drain()
    last_offset = lines[-1][0]
    store.set(last_offset)
    return last_offset


async def run_forwarder(
    cfg: ForwarderConfig,
    *,
    poll_interval: float = 0.5,
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    """Main forwarder loop. Run as a dedicated task.

    Stops when ``stop_event`` is set (used by tests and clean shutdown).
    Exceptions trigger exponential backoff but are never fatal — the
    forwarder is expected to outlive transient master/network failures.
    """
    state_db = cfg.state_db or (cfg.agent_dir / "forwarder.db")
    store = _OffsetStore(state_db)
    offset = store.get()
    backoff = _INITIAL_BACKOFF

    log.info(
        "forwarder start log=%s master=%s:%d offset=%d",
        cfg.log_path, cfg.master_host, cfg.master_port, offset,
    )

    # Host-local bus heartbeat (system.forwarder.health).  Peers on the
    # same host can tail "is the log shipper alive" without hitting the
    # master.  Bus-disabled path is a no-op loop.
    bus = None
    try:
        bus = get_bus(client_name="forwarder")
        await bus.connect()
    except Exception as exc:  # noqa: BLE001
        log.warning("forwarder: bus unavailable, skipping heartbeat: %s", exc)
        bus = None

    heartbeat_task = asyncio.create_task(
        run_health_heartbeat(bus, "forwarder"),
        name="forwarder-bus-heartbeat",
    )

    try:
        while stop_event is None or not stop_event.is_set():
            try:
                ctx = build_worker_ssl_context(cfg.agent_dir)
                reader, writer = await asyncio.open_connection(
                    cfg.master_host, cfg.master_port, ssl=ctx
                )
                log.info("forwarder connected master=%s:%d", cfg.master_host, cfg.master_port)
                backoff = _INITIAL_BACKOFF
                try:
                    offset = await _pump(cfg, store, writer, offset, poll_interval, stop_event)
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:  # nosec B110 — socket cleanup is best-effort
                        pass
                    # Keep reader alive until here to avoid "reader garbage
                    # collected" warnings on some Python builds.
                    del reader
            except (OSError, ssl.SSLError, ConnectionError) as exc:
                log.warning(
                    "forwarder disconnected: %s — retrying in %.1fs", exc, backoff
                )
                try:
                    await asyncio.wait_for(
                        _sleep_unless_stopped(backoff, stop_event), timeout=backoff + 1
                    )
                except asyncio.TimeoutError:
                    pass
                backoff = min(_MAX_BACKOFF, backoff * 2)
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
        except Exception:
            # BUG-16 — don't silently swallow a real heartbeat-task error on
            # shutdown; log it so a failing heartbeat coroutine is visible.
            log.exception("forwarder heartbeat task errored during shutdown")
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()
        store.close()
        log.info("forwarder stopped offset=%d", offset)


async def _pump(
    cfg: ForwarderConfig,
    store: _OffsetStore,
    writer: asyncio.StreamWriter,
    offset: int,
    poll_interval: float,
    stop_event: Optional[asyncio.Event],
) -> int:
    """Read new lines since ``offset`` and ship them until disconnect."""
    while stop_event is None or not stop_event.is_set():
        if not cfg.log_path.exists():
            await _sleep_unless_stopped(poll_interval, stop_event)
            continue

        stat = cfg.log_path.stat()
        if stat.st_size < offset:
            # truncated/rotated — reset.
            log.warning("forwarder log rotated — resetting offset=0")
            offset = 0
            store.set(0)
        if stat.st_size - offset > cfg.max_lag_bytes:
            # Catastrophic lag — skip ahead to cap local disk pressure.
            skip_to = stat.st_size - cfg.max_lag_bytes
            log.warning(
                "forwarder lag %d > cap %d — dropping oldest %d bytes",
                stat.st_size - offset, cfg.max_lag_bytes, skip_to - offset,
            )
            offset = skip_to
            store.set(offset)

        if stat.st_size == offset:
            await _sleep_unless_stopped(poll_interval, stop_event)
            continue

        batch: list[tuple[int, str]] = []
        with open(cfg.log_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            while True:
                line = f.readline()
                if not line or not line.endswith("\n"):
                    break
                offset_after = f.tell()
                batch.append((offset_after, line.rstrip("\n")))
                if len(batch) >= 500:
                    break
        if batch:
            offset = await _send_batch(writer, offset, batch, store)
    return offset


async def _sleep_unless_stopped(
    seconds: float, stop_event: Optional[asyncio.Event]
) -> None:
    if stop_event is None:
        await asyncio.sleep(seconds)
        return
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


# Re-exported for CLI convenience
DEFAULT_PORT = 6514


def default_master_host() -> Optional[str]:
    return os.environ.get("DECNET_SWARM_MASTER_HOST")
