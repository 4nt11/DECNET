# SPDX-License-Identifier: AGPL-3.0-or-later
"""UNIX-socket server for the DECNET bus.

One :class:`BusServer` per host.  Accepts local connections on a UNIX-domain
socket; each connection may:

* publish events (``PUB`` frames) that the server fans out to all matching
  subscribers on other connections, and
* subscribe to patterns (``SUB`` frames) and receive matching events as
  ``EVT`` frames.

Authorization is socket file permissions (0660, group=``decnet`` if that
POSIX group exists, else the server process's own group).  Anything the
kernel lets ``connect()`` is trusted — there is no verb-level auth.  This
matches the "local processes on the same host" threat model; cross-host
federation is out of scope (see DEBT-029).

Backpressure is per-connection, drop-oldest: if a subscriber can't drain its
outbound queue fast enough, the server discards the oldest pending event
rather than blocking publishers.  The bus is at-most-once by contract, so
drops are acceptable; stalled publishers are not.
"""
from __future__ import annotations

import asyncio
import contextlib
import grp
import os
import pathlib
from dataclasses import dataclass, field
from typing import Any

from decnet.bus import protocol
from decnet.bus.base import Event, matches
from decnet.logging import get_logger

log = get_logger("bus.server")

_SOCKET_MODE = 0o660
_DEFAULT_GROUP = "decnet"
_OUTBOUND_QUEUE_SIZE = 1024


@dataclass(eq=False)
class _Connection:
    """Per-connection server state."""

    writer: asyncio.StreamWriter
    peer_name: str = "<unknown>"
    patterns: set[str] = field(default_factory=set)
    outbound: asyncio.Queue[bytes] = field(
        default_factory=lambda: asyncio.Queue(maxsize=_OUTBOUND_QUEUE_SIZE)
    )
    closed: bool = False


class BusServer:
    """Serve a UNIX-socket bus on *socket_path*.

    Lifecycle: construct → :meth:`start` → :meth:`serve_forever` (or rely
    on :meth:`start` returning once bound) → :meth:`close` for teardown.
    Safe to :meth:`close` multiple times.
    """

    def __init__(
        self,
        socket_path: pathlib.Path | str,
        *,
        group: str | None = _DEFAULT_GROUP,
        mode: int = _SOCKET_MODE,
    ) -> None:
        self._path = pathlib.Path(socket_path)
        self._group = group
        self._mode = mode
        self._server: asyncio.base_events.Server | None = None
        self._connections: set[_Connection] = set()
        self._closed = False

    # ─── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Bind the socket and begin accepting connections.

        Removes any stale socket file at *socket_path* first (common case:
        the previous worker crashed without cleaning up).  The parent
        directory must already exist; we do NOT create it blindly because
        the chosen directory (typically ``/run/decnet``) may require
        systemd ``RuntimeDirectory=`` to set up.
        """
        if self._server is not None:
            return

        parent = self._path.parent
        if not parent.exists():
            raise FileNotFoundError(
                f"bus socket parent directory {parent} does not exist; "
                f"create it with systemd RuntimeDirectory= or mkdir"
            )

        # Clean up a stale socket from a previous crash.  If a live server
        # is actually listening there, ``bind()`` below will fail — we do
        # not try to detect live vs. stale ourselves.
        with contextlib.suppress(FileNotFoundError):
            if self._path.is_socket():
                self._path.unlink()

        self._server = await asyncio.start_unix_server(
            self._handle_connection, path=str(self._path),
        )
        _chmod_and_chown(self._path, self._mode, self._group)
        log.info("bus.server: listening on %s (mode=%o group=%s)",
                 self._path, self._mode, self._group or "<inherit>")

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("BusServer not started")
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None

        # Drain every live connection.
        for conn in list(self._connections):
            await self._close_connection(conn)
        self._connections.clear()

        with contextlib.suppress(FileNotFoundError):
            self._path.unlink()
        log.info("bus.server: closed")

    # ─── Internal publish fan-out ───────────────────────────────────────────

    async def publish(self, topic: str, payload: dict[str, Any], event_type: str = "") -> None:
        """Server-side publish helper — used by the worker to emit
        ``system.bus.health`` heartbeats without opening a client loop."""
        event = Event(topic=topic, payload=payload, type=event_type)
        self._fanout(event)

    # ─── Connection handler ─────────────────────────────────────────────────

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        conn = _Connection(writer=writer)
        self._connections.add(conn)
        writer_task = asyncio.create_task(self._writer_loop(conn))
        try:
            await self._reader_loop(conn, reader)
        except protocol.ProtocolError as exc:
            log.warning("bus.server: protocol error from %s: %s", conn.peer_name, exc)
        except (asyncio.IncompleteReadError, ConnectionError) as exc:
            log.debug("bus.server: %s disconnected: %s", conn.peer_name, exc)
        except Exception:  # pragma: no cover - defensive
            log.exception("bus.server: unhandled error in connection")
        finally:
            await self._close_connection(conn)
            self._connections.discard(conn)
            writer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await writer_task

    async def _reader_loop(
        self, conn: _Connection, reader: asyncio.StreamReader,
    ) -> None:
        while True:
            frame = await protocol.read_frame(reader)
            if frame is None:
                return
            await self._dispatch(conn, frame)
            if frame.verb == protocol.BYE:
                return

    async def _dispatch(self, conn: _Connection, frame: protocol.Frame) -> None:
        if frame.verb == protocol.HELLO:
            conn.peer_name = frame.args or conn.peer_name
            log.debug("bus.server: HELLO from %s", conn.peer_name)
            return
        if frame.verb == protocol.SUB:
            pattern = frame.args
            if not pattern:
                raise protocol.ProtocolError("SUB requires a pattern")
            conn.patterns.add(pattern)
            log.debug("bus.server: %s SUB %s", conn.peer_name, pattern)
            return
        if frame.verb == protocol.UNSUB:
            conn.patterns.discard(frame.args)
            return
        if frame.verb == protocol.PUB:
            topic = frame.args
            if not topic:
                raise protocol.ProtocolError("PUB requires a topic")
            data = protocol.decode_body(frame.body) if frame.body else {}
            event = Event(
                topic=topic,
                payload=data.get("payload", {}) or {},
                type=data.get("type", "") or "",
            )
            self._fanout(event, origin=conn)
            return
        if frame.verb == protocol.BYE:
            return
        # EVT is server-to-client only; receiving one is a protocol violation.
        raise protocol.ProtocolError(f"unexpected verb {frame.verb!r} from client")

    def _fanout(self, event: Event, *, origin: _Connection | None = None) -> None:
        """Enqueue *event* as an EVT frame on every matching connection.

        We do NOT deliver back to the originating connection (a publisher
        does not receive its own event).  Encoding happens once per event,
        not once per subscriber.
        """
        try:
            frame_bytes = protocol.encode(
                protocol.EVT, args=event.topic, body=event.to_dict(),
            )
        except protocol.ProtocolError:
            log.exception("bus.server: failed to encode EVT for topic=%s", event.topic)
            return

        for conn in self._connections:
            if conn is origin or conn.closed:
                continue
            if not any(matches(p, event.topic) for p in conn.patterns):
                continue
            _enqueue_drop_oldest(conn.outbound, frame_bytes, event.topic)

    async def _writer_loop(self, conn: _Connection) -> None:
        """Serialize writes onto *conn*'s socket.

        One writer task per connection so a slow peer only blocks its own
        queue, not the fan-out loop.  The queue is bounded with drop-oldest
        policy applied at enqueue time (see :func:`_enqueue_drop_oldest`).
        """
        try:
            while not conn.closed:
                data = await conn.outbound.get()
                conn.writer.write(data)
                await conn.writer.drain()
        except (ConnectionError, BrokenPipeError):
            log.debug("bus.server: %s writer: peer closed", conn.peer_name)
        except asyncio.CancelledError:
            pass
        except Exception:  # pragma: no cover - defensive
            log.exception("bus.server: writer loop crashed for %s", conn.peer_name)

    async def _close_connection(self, conn: _Connection) -> None:
        if conn.closed:
            return
        conn.closed = True
        with contextlib.suppress(Exception):
            conn.writer.close()
            await conn.writer.wait_closed()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _chmod_and_chown(path: pathlib.Path, mode: int, group: str | None) -> None:
    """Apply socket file perms and best-effort group ownership.

    If *group* is ``None`` or the named group does not exist, we leave the
    socket owned by the current process group.  This keeps the server
    usable on dev boxes that don't have a ``decnet`` group set up.
    """
    try:
        os.chmod(path, mode)
    except OSError as exc:
        log.warning("bus.server: chmod(%s, %o) failed: %s", path, mode, exc)

    if not group:
        return
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        log.debug("bus.server: group %r not found, leaving socket group unchanged", group)
        return
    try:
        os.chown(path, -1, gid)
    except PermissionError:
        # Dev box running as an unprivileged user can't chown.  Log once at
        # debug and move on — the socket is still usable by the owner.
        log.debug("bus.server: chown(%s, gid=%d) denied; leaving as-is", path, gid)
    except OSError as exc:
        log.warning("bus.server: chown(%s, gid=%d) failed: %s", path, gid, exc)


def _enqueue_drop_oldest(
    queue: "asyncio.Queue[bytes]", data: bytes, topic: str,
) -> None:
    """Drop-oldest backpressure — mirrors :func:`decnet.bus.fake._enqueue_drop_oldest`."""
    while True:
        try:
            queue.put_nowait(data)
            return
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
                log.warning("bus.server: subscriber queue full, dropped event topic=%s", topic)
            except asyncio.QueueEmpty:
                return
