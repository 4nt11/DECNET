# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for ``decnet.prober.tlscert``.

DER fixtures are synthesized at runtime via ``cryptography`` so we don't
ship a binary blob; failure modes (truncated DER, missing extensions)
are exercised against those fixtures.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from decnet.prober.tlscert import fetch_leaf_cert, parse_leaf_cert


def _build_self_signed_der(
    cn: str = "evil.example.com",
    sans: list[str] | None = None,
    issuer_cn: str | None = None,
) -> bytes:
    """Build a fresh self-signed DER cert. ``issuer_cn`` defaults to ``cn``
    (true self-signed); pass a different value to simulate a CA-issued cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime(2026, 1, 1))
        .not_valid_after(dt.datetime(2027, 1, 1))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


class TestParseLeafCert:

    def test_self_signed_cert_with_sans(self):
        der = _build_self_signed_der(
            cn="evil.example.com",
            sans=["evil.example.com", "c2.example.com"],
        )
        result = parse_leaf_cert(der)
        assert result is not None
        assert result["subject_cn"] == "evil.example.com"
        assert "evil.example.com" in result["issuer"]
        assert result["self_signed"] is True
        assert result["not_before"] == "2026-01-01T00:00:00Z"
        assert result["not_after"] == "2027-01-01T00:00:00Z"
        assert set(result["sans"]) == {"evil.example.com", "c2.example.com"}
        assert result["cert_sha256"] == hashlib.sha256(der).hexdigest()

    def test_cert_without_sans(self):
        der = _build_self_signed_der(cn="single.example", sans=None)
        result = parse_leaf_cert(der)
        assert result is not None
        assert result["sans"] == []

    def test_ca_issued_cert_not_self_signed(self):
        der = _build_self_signed_der(cn="leaf.example", issuer_cn="ca.example")
        result = parse_leaf_cert(der)
        assert result is not None
        assert result["self_signed"] is False

    def test_garbage_der_returns_none(self):
        assert parse_leaf_cert(b"\x00\x01\x02\x03 not a cert") is None

    def test_empty_bytes_returns_none(self):
        assert parse_leaf_cert(b"") is None


class TestFetchLeafCert:

    @patch("decnet.prober.tlscert.ssl.create_default_context")
    @patch("decnet.prober.tlscert.socket.create_connection")
    def test_returns_parsed_cert_on_success(
        self, mock_conn: MagicMock, mock_ctx_factory: MagicMock,
    ):
        der = _build_self_signed_der(cn="ok.example", sans=["ok.example"])

        # Mock the socket context manager
        mock_socket = MagicMock()
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_socket

        # Mock the SSLSocket returned by wrap_socket
        mock_tls = MagicMock()
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)
        mock_tls.getpeercert = MagicMock(return_value=der)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket = MagicMock(return_value=mock_tls)
        mock_ctx_factory.return_value = mock_ctx

        result = fetch_leaf_cert("10.0.0.1", 443, timeout=1.0)
        assert result is not None
        assert result["subject_cn"] == "ok.example"

    @patch("decnet.prober.tlscert.socket.create_connection")
    def test_connect_failure_returns_none(self, mock_conn: MagicMock):
        mock_conn.side_effect = OSError("Connection refused")
        assert fetch_leaf_cert("10.0.0.1", 443, timeout=1.0) is None

    @patch("decnet.prober.tlscert.socket.create_connection")
    def test_handshake_timeout_returns_none(self, mock_conn: MagicMock):
        mock_conn.side_effect = socket.timeout()
        assert fetch_leaf_cert("10.0.0.1", 443, timeout=1.0) is None

    @patch("decnet.prober.tlscert.ssl.create_default_context")
    @patch("decnet.prober.tlscert.socket.create_connection")
    def test_ssl_error_returns_none(
        self, mock_conn: MagicMock, mock_ctx_factory: MagicMock,
    ):
        mock_socket = MagicMock()
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_socket

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket = MagicMock(side_effect=ssl.SSLError("handshake failed"))
        mock_ctx_factory.return_value = mock_ctx

        assert fetch_leaf_cert("10.0.0.1", 443, timeout=1.0) is None

    @patch("decnet.prober.tlscert.ssl.create_default_context")
    @patch("decnet.prober.tlscert.socket.create_connection")
    def test_empty_peer_cert_returns_none(
        self, mock_conn: MagicMock, mock_ctx_factory: MagicMock,
    ):
        mock_socket = MagicMock()
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_socket

        mock_tls = MagicMock()
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)
        mock_tls.getpeercert = MagicMock(return_value=b"")

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket = MagicMock(return_value=mock_tls)
        mock_ctx_factory.return_value = mock_ctx

        assert fetch_leaf_cert("10.0.0.1", 443, timeout=1.0) is None
