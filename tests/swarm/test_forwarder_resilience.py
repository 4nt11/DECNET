# SPDX-License-Identifier: AGPL-3.0-or-later
"""Extra resilience tests for the syslog-over-TLS pipeline.

Covers failure modes the happy-path tests in test_log_forwarder.py don't
exercise:

* log rotation (st_size shrinks under the forwarder) resets offset to 0
  and re-ships from the start;
* listener restart — forwarder reconnects and continues from the last
  persisted offset, no duplicates;
* listener tolerates a client that connects with a valid cert and drops
  mid-frame (IncompleteReadError path) without crashing the server task;
* peer_cn + fingerprint_from_ssl degrade gracefully on missing/invalid
  peer certificates.
"""
from __future__ import annotations

import asyncio
import logging
import pathlib
import socket

import pytest
import ssl

from decnet.swarm import log_forwarder as fwd
from decnet.swarm import log_listener as lst
from decnet.swarm import pki
from decnet.swarm.client import ensure_master_identity


SAMPLE = (
    '<13>1 2026-04-18T00:00:00Z decky01 svc 1 - '
    '[decnet@53595 decky="decky01" service="ssh-service" '
    'event_type="connect" attacker_ip="1.2.3.4" attacker_port="4242"] {msg}\n'
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def _pki_env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    ca_dir = tmp_path / "ca"
    pki.ensure_ca(ca_dir)
    ensure_master_identity(ca_dir)
    worker_dir = tmp_path / "agent"
    issued = pki.issue_worker_cert(pki.load_ca(ca_dir), "worker-y", ["127.0.0.1"])
    pki.write_worker_bundle(issued, worker_dir)
    monkeypatch.setattr(pki, "DEFAULT_CA_DIR", ca_dir)
    monkeypatch.setattr(pki, "DEFAULT_AGENT_DIR", worker_dir)
    return {"ca_dir": ca_dir, "worker_dir": worker_dir}


async def _wait_for(pred, timeout: float = 5.0, interval: float = 0.1) -> bool:
    steps = max(1, int(timeout / interval))
    for _ in range(steps):
        if pred():
            return True
        await asyncio.sleep(interval)
    return False


# ----------------------------------------------------------- pure helpers


def test_worker_ssl_context_pins_tls12_floor(_pki_env: dict) -> None:
    """V9.1.4: forwarder client context must set an explicit TLS 1.2 floor."""
    ctx = fwd.build_worker_ssl_context(_pki_env["worker_dir"])
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_listener_ssl_context_pins_tls12_floor(_pki_env: dict) -> None:
    """V9.1.4: listener server context must set an explicit TLS 1.2 floor."""
    ctx = lst.build_listener_ssl_context(_pki_env["ca_dir"])
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_peer_cn_returns_unknown_when_no_ssl_object() -> None:
    assert lst.peer_cn(None) == "unknown"


def test_fingerprint_from_ssl_handles_missing_peer_cert() -> None:
    assert lst.fingerprint_from_ssl(None) is None


# ---------------------------------------------------- rotation / crash loops


@pytest.mark.asyncio
async def test_forwarder_reships_after_log_rotation(
    tmp_path: pathlib.Path, _pki_env: dict
) -> None:
    """If the log file shrinks (logrotate truncation), the forwarder must
    reset offset=0 and re-ship the new contents — never get stuck past EOF."""
    port = _free_port()
    worker_log = tmp_path / "decnet.log"
    master_log = tmp_path / "master.log"
    master_json = tmp_path / "master.json"

    listener_cfg = lst.ListenerConfig(
        log_path=master_log, json_path=master_json,
        bind_host="127.0.0.1", bind_port=port, ca_dir=_pki_env["ca_dir"],
    )
    fwd_cfg = fwd.ForwarderConfig(
        log_path=worker_log, master_host="127.0.0.1", master_port=port,
        agent_dir=_pki_env["worker_dir"], state_db=tmp_path / "fwd.db",
    )
    stop = asyncio.Event()
    lt = asyncio.create_task(lst.run_listener(listener_cfg, stop_event=stop))
    await asyncio.sleep(0.2)
    ft = asyncio.create_task(fwd.run_forwarder(fwd_cfg, poll_interval=0.05, stop_event=stop))

    # Phase 1: write TWO pre-rotation lines so the offset is deep into the file.
    worker_log.write_text(SAMPLE.format(msg="rotate-A") + SAMPLE.format(msg="rotate-B"))
    ok = await _wait_for(lambda: master_log.exists() and b"rotate-B" in master_log.read_bytes())
    assert ok, "pre-rotation lines never reached master"
    size_before_rotate = master_log.stat().st_size

    # Phase 2: rotate (truncate to a strictly SHORTER content) so the
    # forwarder's offset tracker lands past EOF and must reset to 0.
    worker_log.write_text(SAMPLE.format(msg="P"))

    ok = await _wait_for(
        lambda: master_log.stat().st_size > size_before_rotate
        and master_log.read_text().rstrip().endswith("P"),
        timeout=5.0,
    )
    assert ok, "forwarder got stuck past EOF after rotation (expected reset → ship post-rotate 'P' line)"

    stop.set()
    for t in (ft, lt):
        try:
            await asyncio.wait_for(t, timeout=5)
        except asyncio.TimeoutError:
            t.cancel()


@pytest.mark.asyncio
async def test_forwarder_resumes_after_listener_restart(
    tmp_path: pathlib.Path, _pki_env: dict
) -> None:
    """Listener goes down mid-session, forwarder retries with backoff; on
    restart, we must NOT re-ship lines that were already drained."""
    port = _free_port()
    worker_log = tmp_path / "decnet.log"
    master_log = tmp_path / "master.log"
    master_json = tmp_path / "master.json"
    state_db = tmp_path / "fwd.db"

    listener_cfg = lst.ListenerConfig(
        log_path=master_log, json_path=master_json,
        bind_host="127.0.0.1", bind_port=port, ca_dir=_pki_env["ca_dir"],
    )
    fwd_cfg = fwd.ForwarderConfig(
        log_path=worker_log, master_host="127.0.0.1", master_port=port,
        agent_dir=_pki_env["worker_dir"], state_db=state_db,
    )

    # --- phase 1 ----------------------------------------------------------
    stop1 = asyncio.Event()
    lt1 = asyncio.create_task(lst.run_listener(listener_cfg, stop_event=stop1))
    await asyncio.sleep(0.2)
    stop_fwd = asyncio.Event()
    ft = asyncio.create_task(fwd.run_forwarder(fwd_cfg, poll_interval=0.05, stop_event=stop_fwd))

    worker_log.write_text(SAMPLE.format(msg="before-outage"))
    ok = await _wait_for(lambda: master_log.exists() and b"before-outage" in master_log.read_bytes())
    assert ok, "phase-1 line never reached master"

    # --- outage -----------------------------------------------------------
    stop1.set()
    try:
        await asyncio.wait_for(lt1, timeout=5)
    except asyncio.TimeoutError:
        lt1.cancel()

    # While listener is down, append another line.  Forwarder will retry.
    with open(worker_log, "a", encoding="utf-8") as f:
        f.write(SAMPLE.format(msg="during-outage"))

    await asyncio.sleep(0.3)

    # --- phase 2: listener back ------------------------------------------
    stop2 = asyncio.Event()
    lt2 = asyncio.create_task(lst.run_listener(listener_cfg, stop_event=stop2))

    ok = await _wait_for(lambda: b"during-outage" in master_log.read_bytes(), timeout=15.0)
    assert ok, "forwarder never reshipped the buffered line after listener restart"

    # Crucially, "before-outage" appears exactly once — not re-shipped.
    body = master_log.read_text()
    assert body.count("before-outage") == 1, "forwarder duplicated a line across reconnect"
    assert body.count("during-outage") == 1

    # --- shutdown ---------------------------------------------------------
    stop_fwd.set()
    stop2.set()
    for t in (ft, lt2):
        try:
            await asyncio.wait_for(t, timeout=5)
        except asyncio.TimeoutError:
            t.cancel()


@pytest.mark.asyncio
async def test_listener_tolerates_client_dropping_mid_stream(
    tmp_path: pathlib.Path, _pki_env: dict
) -> None:
    """A well-authenticated client that sends a partial frame and drops must
    not take the listener down or wedge subsequent connections."""
    port = _free_port()
    master_log = tmp_path / "master.log"
    master_json = tmp_path / "master.json"
    listener_cfg = lst.ListenerConfig(
        log_path=master_log, json_path=master_json,
        bind_host="127.0.0.1", bind_port=port, ca_dir=_pki_env["ca_dir"],
    )
    stop = asyncio.Event()
    listener_task = asyncio.create_task(lst.run_listener(listener_cfg, stop_event=stop))
    await asyncio.sleep(0.2)

    try:
        # Client 1: send a truncated octet-count prefix ("99 ") but no payload
        # before closing — exercises IncompleteReadError in read_frame.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            str(_pki_env["worker_dir"] / "worker.crt"),
            str(_pki_env["worker_dir"] / "worker.key"),
        )
        ctx.load_verify_locations(cafile=str(_pki_env["worker_dir"] / "ca.crt"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False

        r, w = await asyncio.open_connection("127.0.0.1", port, ssl=ctx)
        w.write(b"99 ")  # promise 99 bytes, send 0
        await w.drain()
        w.close()
        try:
            await w.wait_closed()
        except Exception:  # nosec B110
            pass

        # Client 2: reconnect cleanly and actually ship a frame.  If the
        # listener survived client-1's misbehavior, this must succeed.
        r2, w2 = await asyncio.open_connection("127.0.0.1", port, ssl=ctx)
        payload = b'<13>1 2026-04-18T00:00:00Z decky01 svc - - - post-drop'
        w2.write(f"{len(payload)} ".encode() + payload)
        await w2.drain()
        w2.close()
        try:
            await w2.wait_closed()
        except Exception:  # nosec B110
            pass

        ok = await _wait_for(
            lambda: master_log.exists() and b"post-drop" in master_log.read_bytes()
        )
        assert ok, "listener got wedged by a mid-frame client drop"
    finally:
        stop.set()
        try:
            await asyncio.wait_for(listener_task, timeout=5)
        except asyncio.TimeoutError:
            listener_task.cancel()


# ----------------------------------------------------- V9.1.3 fail-closed CN


class _FakeWriter:
    """Minimal asyncio.StreamWriter stand-in for _handle_connection.

    Records close()/wait_closed() so a test can assert the connection was
    torn down without binding a real socket.
    """

    def __init__(self, ssl_object: object = None, peername: object = ("1.2.3.4", 4242)) -> None:
        self._extra = {"ssl_object": ssl_object, "peername": peername}
        self.closed = False
        self.wait_closed_called = False
        self.written: list[bytes] = []

    def get_extra_info(self, key: str, default: object = None) -> object:
        return self._extra.get(key, default)

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.wait_closed_called = True

    def write(self, data: bytes) -> None:  # pragma: no cover - not expected
        self.written.append(data)


def _drained_reader(frame: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(frame)
    r.feed_eof()
    return r


@pytest.mark.asyncio
async def test_listener_rejects_unknown_cn_ingests_nothing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V9.1.3 FAIL-CLOSED: a peer whose cert yields CN='unknown'
    (malformed/empty/missing CN) must be closed and ingest NOTHING — even
    though the frame on the wire is a perfectly valid RFC 5424 line."""
    master_log = tmp_path / "master.log"
    master_json = tmp_path / "master.json"
    cfg = lst.ListenerConfig(
        log_path=master_log, json_path=master_json,
        bind_host="127.0.0.1", bind_port=0, ca_dir=tmp_path / "ca",
    )

    # Force peer_cn -> "unknown" regardless of the (absent) ssl object.
    monkeypatch.setattr(lst, "peer_cn", lambda _ssl: "unknown")

    payload = b'<13>1 2026-04-18T00:00:00Z decky01 svc - - - should-not-ingest'
    reader = _drained_reader(f"{len(payload)} ".encode() + payload)
    writer = _FakeWriter()

    await lst._handle_connection(reader, writer, cfg)  # type: ignore[arg-type]

    assert writer.closed, "unknown-CN connection must be closed"
    assert writer.wait_closed_called
    # Nothing must have been ingested into either sink.
    assert not master_log.exists() or master_log.stat().st_size == 0
    assert not master_json.exists() or master_json.stat().st_size == 0


@pytest.mark.asyncio
async def test_listener_processes_valid_cn_normally(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A peer with a parseable CN is still processed and tagged with its
    provenance — the fail-closed guard does not regress the happy path."""
    master_log = tmp_path / "master.log"
    master_json = tmp_path / "master.json"
    cfg = lst.ListenerConfig(
        log_path=master_log, json_path=master_json,
        bind_host="127.0.0.1", bind_port=0, ca_dir=tmp_path / "ca",
    )

    monkeypatch.setattr(lst, "peer_cn", lambda _ssl: "worker-good")

    payload = (
        b'<13>1 2026-04-18T00:00:00Z decky01 svc 1 - '
        b'[decnet@53595 decky="decky01" service="svc" event_type="connect" '
        b'attacker_ip="1.2.3.4" attacker_port="4242"] hello-good'
    )
    reader = _drained_reader(f"{len(payload)} ".encode() + payload)
    writer = _FakeWriter()

    await lst._handle_connection(reader, writer, cfg)  # type: ignore[arg-type]

    assert writer.closed
    assert master_log.exists() and b"hello-good" in master_log.read_bytes()
    # Provenance tagged from the (good) CN in the JSON sink.
    assert master_json.exists() and "worker-good" in master_json.read_text()


# ------------------------------------------------------- BUG-16 shutdown errors


@pytest.mark.asyncio
async def test_listener_shutdown_surfaces_serve_task_error(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BUG-16: a non-CancelledError raised by the serve task during shutdown
    must be logged, not silently swallowed."""

    class _BoomServer:
        def __init__(self) -> None:
            self.sockets: tuple = ()

        async def serve_forever(self) -> None:
            # Run until cancelled, then raise a REAL error instead of honoring
            # the CancelledError — emulates an OSError surfacing as the serve
            # task is awaited after server.close()/cancel() during shutdown.
            try:
                await asyncio.Event().wait()  # block until cancelled
            except asyncio.CancelledError:
                raise OSError("boom during serve") from None

        def close(self) -> None:
            pass

        async def __aenter__(self) -> "_BoomServer":
            return self

        async def __aexit__(self, *exc: object) -> None:
            pass

    async def _fake_start_server(*_a: object, **_kw: object) -> _BoomServer:
        return _BoomServer()

    monkeypatch.setattr(lst.asyncio, "start_server", _fake_start_server)
    monkeypatch.setattr(lst, "build_listener_ssl_context", lambda _ca: None)

    cfg = lst.ListenerConfig(
        log_path=tmp_path / "m.log", json_path=tmp_path / "m.json",
        bind_host="127.0.0.1", bind_port=0, ca_dir=tmp_path / "ca",
    )
    stop = asyncio.Event()

    async def _stop_soon() -> None:
        # Let the serve task actually start before we request shutdown, so
        # the cancel path (not a never-scheduled task) is what surfaces.
        await asyncio.sleep(0.05)
        stop.set()

    waiter = asyncio.create_task(_stop_soon())
    with caplog.at_level(logging.ERROR, logger="swarm.listener"):
        await lst.run_listener(cfg, stop_event=stop)
    await waiter

    assert any(
        "serve task errored during shutdown" in r.getMessage() for r in caplog.records
    ), "listener swallowed a real serve-task error on shutdown"


@pytest.mark.asyncio
async def test_forwarder_shutdown_surfaces_heartbeat_error(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BUG-16: a non-CancelledError from the heartbeat task during forwarder
    shutdown must be logged, not silently suppressed."""

    started = asyncio.Event()

    async def _boom_heartbeat(*_a: object, **_kw: object) -> None:
        # Signal that we actually ran, then fail — guarantees the task has a
        # stored exception (not just a pending cancel) by shutdown time.
        started.set()
        raise RuntimeError("heartbeat boom")

    # Bus unavailable -> bus=None path; heartbeat task still created.
    def _no_bus(*_a: object, **_kw: object):
        raise RuntimeError("no bus in test")

    # Make the connect attempt fail with OSError so run_forwarder takes its
    # caught backoff branch (which yields control, letting the heartbeat task
    # run and raise) instead of propagating an uncaught error.
    def _boom_ctx(*_a: object, **_kw: object):
        raise OSError("no ssl context in test")

    monkeypatch.setattr(fwd, "get_bus", _no_bus)
    monkeypatch.setattr(fwd, "run_health_heartbeat", _boom_heartbeat)
    monkeypatch.setattr(fwd, "build_worker_ssl_context", _boom_ctx)

    cfg = fwd.ForwarderConfig(
        log_path=tmp_path / "decnet.log",
        master_host="127.0.0.1", master_port=0,
        agent_dir=tmp_path / "agent",
        state_db=tmp_path / "fwd.db",
    )
    stop = asyncio.Event()

    async def _stop_after_heartbeat_ran() -> None:
        # Let the heartbeat task get scheduled and raise before we ask the
        # forwarder to shut down, so the finally block observes the error.
        await started.wait()
        stop.set()

    waiter = asyncio.create_task(_stop_after_heartbeat_ran())
    with caplog.at_level(logging.ERROR, logger="swarm.forwarder"):
        await fwd.run_forwarder(cfg, poll_interval=0.01, stop_event=stop)
    await waiter

    assert any(
        "heartbeat task errored during shutdown" in r.getMessage() for r in caplog.records
    ), "forwarder swallowed a real heartbeat-task error on shutdown"
