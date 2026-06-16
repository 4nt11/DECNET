# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the syslog-over-TLS pipeline.

Covers:
* octet-counted framing encode/decode (pure functions);
* offset persistence across reopens;
* end-to-end mTLS roundtrip forwarder → listener;
* impostor-CA worker is rejected at TLS handshake.
"""
from __future__ import annotations

import asyncio
import pathlib
import socket

import pytest
import ssl

from decnet.swarm import log_forwarder as fwd
from decnet.swarm import log_listener as lst
from decnet.swarm import pki
from decnet.swarm.client import ensure_master_identity


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ------------------------------------------------------------ pure framing


def test_encode_frame_matches_rfc5425_shape() -> None:
    out = fwd.encode_frame("<13>1 2026-04-18T00:00:00Z decky01 svc - - - hi")
    # "<len> <msg>" — ASCII digits, space, then the UTF-8 payload.
    assert out.startswith(b"47 ")
    assert out.endswith(b"hi")
    assert int(out.split(b" ", 1)[0]) == len(out.split(b" ", 1)[1])


@pytest.mark.asyncio
async def test_read_frame_roundtrip() -> None:
    payload = b"<13>1 2026-04-18T00:00:00Z host app - - - msg"
    frame = fwd.encode_frame(payload.decode())
    reader = asyncio.StreamReader()
    reader.feed_data(frame)
    reader.feed_eof()
    got = await fwd.read_frame(reader)
    assert got == payload


@pytest.mark.asyncio
async def test_read_frame_rejects_bad_prefix() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"NOTANUMBER msg")
    reader.feed_eof()
    with pytest.raises(ValueError):
        await fwd.read_frame(reader)


# ------------------------------------------------------------- offset store


def test_offset_store_persists_across_reopen(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "fwd.db"
    s1 = fwd._OffsetStore(db)
    assert s1.get() == 0
    s1.set(4242)
    s1.close()

    s2 = fwd._OffsetStore(db)
    assert s2.get() == 4242
    s2.close()


# ------------------------------------------------------------ TLS roundtrip


@pytest.fixture
def _pki_env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    ca_dir = tmp_path / "ca"
    pki.ensure_ca(ca_dir)
    # Master identity (also used as listener server cert).
    master_id = ensure_master_identity(ca_dir)
    # Give master's cert a 127.0.0.1 SAN so workers can resolve it if they
    # happen to enable check_hostname; we don't, but future-proof anyway.
    # (The default ensure_master_identity() cert already has 127.0.0.1.)
    _ = master_id

    # Worker bundle — enrolled with 127.0.0.1 SAN.
    worker_dir = tmp_path / "agent"
    issued = pki.issue_worker_cert(pki.load_ca(ca_dir), "worker-x", ["127.0.0.1"])
    pki.write_worker_bundle(issued, worker_dir)

    monkeypatch.setattr(pki, "DEFAULT_CA_DIR", ca_dir)
    monkeypatch.setattr(pki, "DEFAULT_AGENT_DIR", worker_dir)
    return {"ca_dir": ca_dir, "worker_dir": worker_dir}


@pytest.mark.asyncio
async def test_forwarder_to_listener_roundtrip(
    tmp_path: pathlib.Path, _pki_env: dict
) -> None:
    port = _free_port()
    worker_log = tmp_path / "decnet.log"
    worker_log.write_text("")  # create empty

    master_log = tmp_path / "master.log"
    master_json = tmp_path / "master.json"

    listener_cfg = lst.ListenerConfig(
        log_path=master_log,
        json_path=master_json,
        bind_host="127.0.0.1",
        bind_port=port,
        ca_dir=_pki_env["ca_dir"],
    )
    fwd_cfg = fwd.ForwarderConfig(
        log_path=worker_log,
        master_host="127.0.0.1",
        master_port=port,
        agent_dir=_pki_env["worker_dir"],
        state_db=tmp_path / "fwd.db",
    )
    stop = asyncio.Event()

    listener_task = asyncio.create_task(lst.run_listener(listener_cfg, stop_event=stop))
    await asyncio.sleep(0.2)  # wait for bind

    forwarder_task = asyncio.create_task(
        fwd.run_forwarder(fwd_cfg, poll_interval=0.05, stop_event=stop)
    )

    # Write a few RFC 5424-ish lines into the worker log.
    sample = (
        '<13>1 2026-04-18T00:00:00Z decky01 ssh-service 1 - '
        '[decnet@53595 decky="decky01" service="ssh-service" event_type="connect" '
        'attacker_ip="1.2.3.4" attacker_port="4242"] ssh connect\n'
    )
    with open(worker_log, "a", encoding="utf-8") as f:
        for _ in range(3):
            f.write(sample)

    # Poll for delivery on the master side.
    for _ in range(50):
        if master_log.exists() and master_log.stat().st_size > 0:
            break
        await asyncio.sleep(0.1)

    stop.set()
    for t in (forwarder_task, listener_task):
        try:
            await asyncio.wait_for(t, timeout=5)
        except asyncio.TimeoutError:
            t.cancel()

    assert master_log.exists()
    body = master_log.read_text()
    assert body.count("ssh connect") == 3
    # Worker provenance tagged in the JSON sink.
    assert master_json.exists()
    assert "worker-x" in master_json.read_text()


@pytest.mark.asyncio
async def test_forwarder_resumes_from_persisted_offset(
    tmp_path: pathlib.Path, _pki_env: dict
) -> None:
    """Simulate a listener outage: forwarder persists offset locally and,
    after the listener comes back, only ships lines added AFTER the crash."""
    port = _free_port()
    worker_log = tmp_path / "decnet.log"
    master_log = tmp_path / "master.log"
    master_json = tmp_path / "master.json"
    state_db = tmp_path / "fwd.db"

    # Pre-populate 2 lines and the offset store as if a previous forwarder run
    # had already delivered them.  The new run must NOT re-ship them.
    line = (
        '<13>1 2026-04-18T00:00:00Z decky01 svc 1 - [x] old\n'
    )
    worker_log.write_text(line * 2)
    seed = fwd._OffsetStore(state_db)
    seed.set(len(line) * 2)
    seed.close()

    listener_cfg = lst.ListenerConfig(
        log_path=master_log, json_path=master_json,
        bind_host="127.0.0.1", bind_port=port, ca_dir=_pki_env["ca_dir"],
    )
    fwd_cfg = fwd.ForwarderConfig(
        log_path=worker_log, master_host="127.0.0.1", master_port=port,
        agent_dir=_pki_env["worker_dir"], state_db=state_db,
    )
    stop = asyncio.Event()
    lt = asyncio.create_task(lst.run_listener(listener_cfg, stop_event=stop))
    await asyncio.sleep(0.2)
    ft = asyncio.create_task(fwd.run_forwarder(fwd_cfg, poll_interval=0.05, stop_event=stop))

    # Append a NEW line after startup — only this should reach the master.
    new_line = (
        '<13>1 2026-04-18T00:00:01Z decky01 svc 1 - [x] fresh\n'
    )
    with open(worker_log, "a", encoding="utf-8") as f:
        f.write(new_line)

    for _ in range(50):
        if master_log.exists() and b"fresh" in master_log.read_bytes():
            break
        await asyncio.sleep(0.1)

    stop.set()
    for t in (ft, lt):
        try:
            await asyncio.wait_for(t, timeout=5)
        except asyncio.TimeoutError:
            t.cancel()

    body = master_log.read_text()
    assert "fresh" in body
    assert "old" not in body, "forwarder re-shipped lines already acked before restart"


@pytest.mark.asyncio
async def test_impostor_worker_rejected_at_tls(
    tmp_path: pathlib.Path, _pki_env: dict
) -> None:
    port = _free_port()
    master_log = tmp_path / "master.log"
    master_json = tmp_path / "master.json"
    listener_cfg = lst.ListenerConfig(
        log_path=master_log,
        json_path=master_json,
        bind_host="127.0.0.1",
        bind_port=port,
        ca_dir=_pki_env["ca_dir"],
    )
    stop = asyncio.Event()
    listener_task = asyncio.create_task(lst.run_listener(listener_cfg, stop_event=stop))
    await asyncio.sleep(0.2)

    try:
        # Build a forwarder SSL context from a DIFFERENT CA — should be rejected.
        evil_ca = pki.generate_ca("Evil CA")
        evil_dir = tmp_path / "evil"
        pki.write_worker_bundle(
            pki.issue_worker_cert(evil_ca, "evil-worker", ["127.0.0.1"]), evil_dir
        )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(str(evil_dir / "worker.crt"), str(evil_dir / "worker.key"))
        ctx.load_verify_locations(cafile=str(evil_dir / "ca.crt"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False

        rejected = False
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port, ssl=ctx)
            # If TLS somehow succeeded, push a byte and expect the server to drop.
            w.write(b"5 hello")
            await w.drain()
            # If the server accepted this from an unknown CA, that's a failure.
            await asyncio.sleep(0.2)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
        except (ssl.SSLError, OSError, ConnectionError):
            rejected = True

        assert rejected or master_log.stat().st_size == 0, (
            "impostor connection must be rejected or produce no log lines"
        )
    finally:
        stop.set()
        try:
            await asyncio.wait_for(listener_task, timeout=5)
        except asyncio.TimeoutError:
            listener_task.cancel()
