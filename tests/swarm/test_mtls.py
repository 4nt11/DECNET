# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the shared swarm mTLS peer-identity helper (``_mtls``).

No live TLS: peer certs are minted via the real PKI and fed in through a
fabricated ASGI scope, exactly the way uvicorn's TLS-scope shim would.
"""
from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import pytest

from decnet.swarm import pki
from decnet.web.router.swarm import _mtls


# ------------------------- cert fixtures ------------------------------------


@pytest.fixture
def ca(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pki, "DEFAULT_CA_DIR", tmp_path / "ca")
    return pki.ensure_ca()


def _der_for(ca, cn: str) -> bytes:
    """Issue a cert with the given CN and return its DER bytes."""
    from cryptography import x509

    issued = pki.issue_worker_cert(ca, cn, [])
    cert = x509.load_pem_x509_certificate(issued.cert_pem)
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.DER)


def _scope_with(der: bytes) -> dict:
    return {"extensions": {"tls": {"client_cert_chain": [der]}}}


# ------------------------- extraction --------------------------------------


def test_extract_peer_cert_parses_fingerprint_and_cn(ca) -> None:
    der = _der_for(ca, "decnet-master")
    peer = _mtls.extract_peer_cert(_scope_with(der))
    assert peer is not None
    assert peer.sha256 == hashlib.sha256(der).hexdigest().lower()
    assert peer.cn == "decnet-master"


def test_extract_peer_cert_fallback_transport_path(ca) -> None:
    der = _der_for(ca, "swarmctl")
    ssl_obj = MagicMock()
    ssl_obj.getpeercert.return_value = der
    transport = MagicMock()
    transport.get_extra_info.return_value = ssl_obj

    peer = _mtls.extract_peer_cert({"transport": transport})
    assert peer is not None and peer.cn == "swarmctl"
    ssl_obj.getpeercert.assert_called_with(binary_form=True)


def test_extract_peer_cert_none_when_no_cert() -> None:
    assert _mtls.extract_peer_cert({}) is None


def test_extract_fingerprint_works_on_non_cert_der() -> None:
    # Fingerprint must be computed even when the bytes aren't a parseable
    # cert (CN parse fails → None), matching the heartbeat unit tests.
    der = b"\x30\x82not-a-real-cert"
    scope = _scope_with(der)
    assert _mtls.extract_peer_fingerprint(scope) == hashlib.sha256(der).hexdigest()
    peer = _mtls.extract_peer_cert(scope)
    assert peer is not None and peer.cn is None


# ------------------------- require_operator_cert ---------------------------


def _request_with(scope: dict) -> MagicMock:
    req = MagicMock()
    req.scope = scope
    return req


def test_require_operator_accepts_master(ca) -> None:
    peer = _mtls.require_operator_cert(_request_with(_scope_with(_der_for(ca, "decnet-master"))))
    assert peer.cn == "decnet-master"


def test_require_operator_accepts_swarmctl(ca) -> None:
    peer = _mtls.require_operator_cert(_request_with(_scope_with(_der_for(ca, "swarmctl"))))
    assert peer.cn == "swarmctl"


def test_require_operator_rejects_worker_cn(ca) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as ei:
        _mtls.require_operator_cert(_request_with(_scope_with(_der_for(ca, "worker-1"))))
    assert ei.value.status_code == 403


def test_require_operator_rejects_updater_cn(ca) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as ei:
        _mtls.require_operator_cert(_request_with(_scope_with(_der_for(ca, "updater@worker-1"))))
    assert ei.value.status_code == 403


def test_require_operator_rejects_no_cert() -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as ei:
        _mtls.require_operator_cert(_request_with({}))
    assert ei.value.status_code == 403
    assert "unavailable" in ei.value.detail
