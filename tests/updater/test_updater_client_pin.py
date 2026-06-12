# SPDX-License-Identifier: AGPL-3.0-or-later
"""UpdaterClient SHA-256 leaf-cert pinning (master->worker updater channel).

The updater channel pip-installs code as root, so it pins the worker's
updater leaf cert against ``SwarmHost.updater_cert_fingerprint`` and fails
closed on mismatch OR a missing recorded fingerprint.

We don't need the real updater ASGI app: ``UpdaterClient.__aenter__`` runs
``_verify_pin`` which opens its own throwaway TLS connection to extract the
peer leaf cert before any RPC. A minimal threaded mTLS socket server that
simply completes the handshake is enough to exercise the pin.
"""
from __future__ import annotations

import pathlib
import socket
import ssl
import threading
import time

import pytest

from decnet.swarm import client as swarm_client
from decnet.swarm import pki
from decnet.swarm.updater_client import UpdaterClient


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _MiniTLSServer:
    """Threaded mTLS server that accepts a connection, completes the
    handshake (presenting the worker leaf cert), then closes."""

    def __init__(self, worker_dir: pathlib.Path, port: int) -> None:
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(
            str(worker_dir / "worker.crt"), str(worker_dir / "worker.key")
        )
        self._ctx.load_verify_locations(cafile=str(worker_dir / "ca.crt"))
        self._ctx.verify_mode = ssl.CERT_REQUIRED
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                tls = self._ctx.wrap_socket(conn, server_side=True)
                try:
                    tls.recv(64)
                except OSError:
                    pass
                tls.close()
            except OSError:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


@pytest.fixture
def updater_env(tmp_path: pathlib.Path):
    ca_dir = tmp_path / "ca"
    pki.ensure_ca(ca_dir)
    worker_dir = tmp_path / "updater"
    pki.write_worker_bundle(
        pki.issue_worker_cert(pki.load_ca(ca_dir), "updater-test", ["127.0.0.1"]),
        worker_dir,
    )
    master_id = swarm_client.ensure_master_identity(ca_dir)

    port = _free_port()
    server = _MiniTLSServer(worker_dir, port)
    server.start()
    # Give the listener a moment.
    time.sleep(0.1)
    try:
        yield worker_dir, port, master_id
    finally:
        server.stop()


@pytest.mark.asyncio
async def test_pin_accepts_matching_fingerprint(updater_env) -> None:
    worker_dir, port, master_id = updater_env
    expected = pki.fingerprint((worker_dir / "worker.crt").read_bytes())
    host = {
        "uuid": "h1",
        "name": "updater-test",
        "address": "127.0.0.1",
        "updater_cert_fingerprint": expected,
    }
    async with UpdaterClient(
        host=host, updater_port=port, identity=master_id
    ) as u:
        # Entering the context already ran _verify_pin successfully.
        assert u._expected_fingerprint == expected.lower()


@pytest.mark.asyncio
async def test_pin_rejects_mismatch(updater_env) -> None:
    _worker_dir, port, master_id = updater_env
    host = {
        "uuid": "h1",
        "name": "updater-test",
        "address": "127.0.0.1",
        "updater_cert_fingerprint": "0" * 64,
    }
    with pytest.raises(swarm_client.FingerprintMismatchError):
        async with UpdaterClient(host=host, updater_port=port, identity=master_id):
            pass


@pytest.mark.asyncio
async def test_pin_rejects_missing_fingerprint(updater_env) -> None:
    """Fail closed: a host with no recorded updater fingerprint is refused
    (unlike AgentClient, the updater channel never falls through to CA-only)."""
    _worker_dir, port, master_id = updater_env
    host = {
        "uuid": "h1",
        "name": "updater-test",
        "address": "127.0.0.1",
        "updater_cert_fingerprint": None,
    }
    with pytest.raises(swarm_client.FingerprintMismatchError):
        async with UpdaterClient(host=host, updater_port=port, identity=master_id):
            pass


def test_verify_hostname_defaults_to_env_flag(monkeypatch) -> None:
    """The verify_hostname kwarg defaults to DECNET_VERIFY_HOSTNAME, which
    now defaults to True (operators opt OUT explicitly)."""
    import decnet.env as env

    monkeypatch.setattr(env, "DECNET_VERIFY_HOSTNAME", True)
    c_default = UpdaterClient(address="127.0.0.1", updater_port=9)
    assert c_default._verify_hostname is True

    monkeypatch.setattr(env, "DECNET_VERIFY_HOSTNAME", False)
    c_off = UpdaterClient(address="127.0.0.1", updater_port=9)
    assert c_off._verify_hostname is False

    # Explicit kwarg overrides the env default.
    c_explicit = UpdaterClient(
        address="127.0.0.1", updater_port=9, verify_hostname=True
    )
    assert c_explicit._verify_hostname is True


@pytest.mark.asyncio
async def test_build_client_constructs_with_flag(updater_env) -> None:
    """_build_client must construct a client for both flag values without
    error; check_hostname is wired from self._verify_hostname (verified via
    the live handshake in the pin tests above, which use verify_hostname
    from the env default)."""
    import httpx

    _worker_dir, port, master_id = updater_env
    for flag in (True, False):
        c = UpdaterClient(
            address="127.0.0.1", updater_port=port, identity=master_id,
            verify_hostname=flag,
        )
        built = c._build_client(httpx.Timeout(5.0))
        assert isinstance(built, httpx.AsyncClient)
        assert c._verify_hostname is flag
        await built.aclose()


@pytest.mark.asyncio
async def test_build_client_pins_tls12_floor(updater_env, monkeypatch) -> None:
    """V9.1.4 sweep: the updater mTLS client context pins a TLS 1.2 floor.

    The context is embedded in _build_client (passed to httpx as verify=), so
    spy on httpx.AsyncClient to capture the real context and assert the floor.
    Spying on httpx (not ssl) leaves the genuine SSLContext setter intact.
    """
    import ssl as _ssl
    import httpx
    from decnet.swarm import updater_client as uc

    captured: dict[str, object] = {}
    real_client = httpx.AsyncClient

    def _spy(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured["verify"] = kwargs.get("verify")
        return real_client(*args, **kwargs)

    monkeypatch.setattr(uc.httpx, "AsyncClient", _spy)
    _worker_dir, port, master_id = updater_env
    c = UpdaterClient(address="127.0.0.1", updater_port=port, identity=master_id)
    built = c._build_client(httpx.Timeout(5.0))
    try:
        ctx = captured.get("verify")
        assert isinstance(ctx, _ssl.SSLContext), "context not passed to httpx"
        assert ctx.minimum_version == _ssl.TLSVersion.TLSv1_2
    finally:
        await built.aclose()
