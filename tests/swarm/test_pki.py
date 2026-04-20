"""PKI roundtrip tests for the DECNET swarm CA."""
from __future__ import annotations

import pathlib
import ssl
import threading
import socket
import time

import pytest
from cryptography import x509

from decnet.swarm import pki


def test_ensure_ca_is_idempotent(tmp_path: pathlib.Path) -> None:
    ca_dir = tmp_path / "ca"
    first = pki.ensure_ca(ca_dir)
    second = pki.ensure_ca(ca_dir)
    assert first.key_pem == second.key_pem
    assert first.cert_pem == second.cert_pem


def test_issue_worker_cert_signed_by_ca(tmp_path: pathlib.Path) -> None:
    ca = pki.ensure_ca(tmp_path / "ca")
    issued = pki.issue_worker_cert(ca, "worker-01", ["127.0.0.1", "worker-01"])
    cert = x509.load_pem_x509_certificate(issued.cert_pem)
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)
    assert cert.issuer == ca_cert.subject
    # SAN should include both the hostname AND the IP we supplied
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_names = set(san.get_values_for_type(x509.DNSName))
    ip_values = {str(v) for v in san.get_values_for_type(x509.IPAddress)}
    assert "worker-01" in dns_names
    assert "127.0.0.1" in ip_values


def test_worker_bundle_roundtrip(tmp_path: pathlib.Path) -> None:
    ca = pki.ensure_ca(tmp_path / "ca")
    issued = pki.issue_worker_cert(ca, "worker-02", ["127.0.0.1"])
    agent_dir = tmp_path / "agent"
    pki.write_worker_bundle(issued, agent_dir)
    # File perms: worker.key must not be world-readable.
    mode = (agent_dir / "worker.key").stat().st_mode & 0o777
    assert mode == 0o600
    loaded = pki.load_worker_bundle(agent_dir)
    assert loaded is not None
    assert loaded.fingerprint_sha256 == issued.fingerprint_sha256


def test_load_worker_bundle_returns_none_if_missing(tmp_path: pathlib.Path) -> None:
    assert pki.load_worker_bundle(tmp_path / "empty") is None


def test_ensure_swarmctl_cert_issues_from_same_ca(tmp_path: pathlib.Path) -> None:
    ca_dir = tmp_path / "ca"
    swarmctl_dir = tmp_path / "swarmctl"
    cert_path, key_path, ca_path = pki.ensure_swarmctl_cert(
        "0.0.0.0", ca_dir=ca_dir, swarmctl_dir=swarmctl_dir
    )
    assert cert_path.exists() and key_path.exists() and ca_path.exists()
    # Server cert is signed by the same CA that workers will ship — that's
    # the whole point of the auto-issue path.
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
    assert cert.issuer == ca_cert.subject
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ips = {str(v) for v in san.get_values_for_type(x509.IPAddress)}
    dns = set(san.get_values_for_type(x509.DNSName))
    assert "0.0.0.0" in ips
    assert "localhost" in dns
    # Key perm is the same 0600 we enforce on worker.key.
    assert (key_path.stat().st_mode & 0o777) == 0o600


def test_ensure_swarmctl_cert_is_idempotent(tmp_path: pathlib.Path) -> None:
    # Second call must NOT re-issue — otherwise a restart of swarmctl
    # would rotate the server cert and break any worker mid-TLS-session.
    ca_dir = tmp_path / "ca"
    swarmctl_dir = tmp_path / "swarmctl"
    first = pki.ensure_swarmctl_cert("0.0.0.0", ca_dir=ca_dir, swarmctl_dir=swarmctl_dir)
    first_pem = first[0].read_bytes()
    second = pki.ensure_swarmctl_cert("0.0.0.0", ca_dir=ca_dir, swarmctl_dir=swarmctl_dir)
    assert second[0].read_bytes() == first_pem


def test_fingerprint_stable_across_calls(tmp_path: pathlib.Path) -> None:
    ca = pki.ensure_ca(tmp_path / "ca")
    issued = pki.issue_worker_cert(ca, "worker-03", ["127.0.0.1"])
    assert pki.fingerprint(issued.cert_pem) == issued.fingerprint_sha256


def test_mtls_handshake_round_trip(tmp_path: pathlib.Path) -> None:
    """End-to-end: issue two worker certs from the same CA, have one act as
    TLS server and the other as TLS client, and confirm the handshake
    succeeds with mutual auth.
    """
    ca = pki.ensure_ca(tmp_path / "ca")
    srv_dir = tmp_path / "srv"
    cli_dir = tmp_path / "cli"
    pki.write_worker_bundle(
        pki.issue_worker_cert(ca, "srv", ["127.0.0.1"]), srv_dir
    )
    pki.write_worker_bundle(
        pki.issue_worker_cert(ca, "cli", ["127.0.0.1"]), cli_dir
    )

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(srv_dir / "worker.crt"), str(srv_dir / "worker.key"))
    server_ctx.load_verify_locations(cafile=str(srv_dir / "ca.crt"))
    server_ctx.verify_mode = ssl.CERT_REQUIRED

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_cert_chain(str(cli_dir / "worker.crt"), str(cli_dir / "worker.key"))
    client_ctx.load_verify_locations(cafile=str(cli_dir / "ca.crt"))
    client_ctx.check_hostname = False  # SAN matches IP, not hostname
    client_ctx.verify_mode = ssl.CERT_REQUIRED

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    result: dict[str, object] = {}

    def _serve() -> None:
        try:
            conn, _ = sock.accept()
            with server_ctx.wrap_socket(conn, server_side=True) as tls:
                result["peer_cert"] = tls.getpeercert()
                tls.sendall(b"ok")
        except Exception as exc:  # noqa: BLE001
            result["error"] = repr(exc)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    time.sleep(0.05)

    with socket.create_connection(("127.0.0.1", port)) as raw:
        with client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
            assert tls.recv(2) == b"ok"

    t.join(timeout=2)
    sock.close()
    assert "error" not in result, result.get("error")
    assert result.get("peer_cert"), "server did not receive client cert"


def test_unauthenticated_client_rejected(tmp_path: pathlib.Path) -> None:
    """A client presenting a cert from a DIFFERENT CA must be rejected."""
    good_ca = pki.ensure_ca(tmp_path / "good-ca")
    evil_ca = pki.generate_ca("Evil CA")

    srv_dir = tmp_path / "srv"
    pki.write_worker_bundle(
        pki.issue_worker_cert(good_ca, "srv", ["127.0.0.1"]), srv_dir
    )

    evil_dir = tmp_path / "evil"
    pki.write_worker_bundle(
        pki.issue_worker_cert(evil_ca, "evil", ["127.0.0.1"]), evil_dir
    )

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(srv_dir / "worker.crt"), str(srv_dir / "worker.key"))
    server_ctx.load_verify_locations(cafile=str(srv_dir / "ca.crt"))
    server_ctx.verify_mode = ssl.CERT_REQUIRED

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_cert_chain(str(evil_dir / "worker.crt"), str(evil_dir / "worker.key"))
    # The evil client still trusts its own CA for the server cert (so the
    # server cert chain verifies from its side); the server-side rejection
    # is what we are asserting.
    client_ctx.load_verify_locations(cafile=str(srv_dir / "ca.crt"))
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_REQUIRED

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    errors: list[str] = []

    def _serve() -> None:
        try:
            conn, _ = sock.accept()
            with server_ctx.wrap_socket(conn, server_side=True):
                pass
        except ssl.SSLError as exc:
            errors.append(repr(exc))
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    time.sleep(0.05)

    # Rejection may surface on either side (SSL alert on the server closes the
    # socket — client may see SSLError, ConnectionResetError, or EOF).
    handshake_failed = False
    try:
        with socket.create_connection(("127.0.0.1", port)) as raw:
            with client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.do_handshake()
    except (ssl.SSLError, OSError):
        handshake_failed = True

    t.join(timeout=2)
    sock.close()
    assert handshake_failed or errors, (
        "server should have rejected the evil-CA-signed client cert"
    )
