# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared mTLS peer-identity extraction + authorization for the swarm control plane.

The swarm controller (``decnet/web/swarm_api.py``) and the per-worker updater
(``decnet/updater/app.py``) both run behind uvicorn with ``--ssl-cert-reqs 2``
(``ssl.CERT_REQUIRED``), so the transport layer guarantees the peer cert is
CA-signed.  This module turns that transport guarantee into an *application*
identity check: it pulls the peer cert out of the ASGI scope and exposes both
its SHA-256 fingerprint (for per-host pinning) and its CN (for role
distinction).

Role distinction is by CN, which the PKI already assigns per identity
(``decnet/swarm/pki.py:issue_worker_cert``):

    decnet-master        master / operator client
    swarmctl             operator CLI server identity
    {agent_name}         worker agent
    updater@{agent_name} per-worker updater

Two extraction paths are tried because uvicorn has stashed the peer cert in
different scope slots across versions; both this module and the heartbeat
endpoint fail closed when neither yields a cert.
"""
from __future__ import annotations

import hashlib
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Any, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from fastapi import HTTPException, Request

from decnet.logging import get_logger

log = get_logger("swarm.mtls")

# Operator identities permitted to drive the control plane (enroll / deploy /
# teardown / host management).  Worker and updater certs are intentionally
# excluded — a worker's still-valid cert must not be able to enroll new hosts
# or tear the fleet down.
OPERATOR_CNS = frozenset({"decnet-master", "swarmctl"})

# Hosts treated as "the master box itself". A certless request is only accepted
# from these — the single-operator loopback boundary (same model as
# docker.sock). Any routable bind is forced onto mTLS by the swarmctl startup
# guard, so a certless request can never legitimately arrive from off-box.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


@dataclass(frozen=True)
class PeerCert:
    """The TLS peer's identity, extracted from the ASGI scope."""

    sha256: str
    cn: Optional[str]


def _extract_peer_der(scope: MutableMapping[str, Any]) -> Optional[bytes]:
    """Pull the DER-encoded peer cert from an ASGI scope, or None.

    1. Primary: ``scope["extensions"]["tls"]["client_cert_chain"][0]``
       (uvicorn >= 0.30 ASGI TLS extension).
    2. Fallback: the transport's ``ssl_object.getpeercert(binary_form=True)``
       (older uvicorn builds + some other servers).
    """
    peer_der: Optional[bytes] = None
    source = "none"

    try:
        chain = scope.get("extensions", {}).get("tls", {}).get("client_cert_chain")
        if chain:
            peer_der = chain[0]
            source = "primary"
    except (AttributeError, KeyError, TypeError):
        # scope["extensions"]["tls"] structure varies across uvicorn versions
        peer_der = None

    if peer_der is None:
        transport = scope.get("transport")
        try:
            ssl_obj = transport.get_extra_info("ssl_object") if transport else None
            if ssl_obj is not None:
                peer_der = ssl_obj.getpeercert(binary_form=True)
                if peer_der:
                    source = "fallback"
        except (AttributeError, OSError):
            # transport may not be an SSL transport, or the handshake may be incomplete
            peer_der = None

    if not peer_der:
        log.debug("peer cert extraction failed via none")
        return None

    log.debug("peer cert extraction succeeded via %s", source)
    return peer_der


def _cn_from_der(der: bytes) -> Optional[str]:
    """Best-effort CN parse. Returns None on any malformed/CN-less cert.

    Never raises: a fingerprint is still usable for pinning even when the
    subject can't be parsed, so callers decide what a missing CN means.
    """
    try:
        cert = x509.load_der_x509_certificate(der)
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            return None
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8", "replace")
    except (ValueError, TypeError, IndexError, UnicodeDecodeError):
        return None


def extract_peer_cert(scope: MutableMapping[str, Any]) -> Optional[PeerCert]:
    """Return the peer's ``PeerCert`` (fingerprint + CN), or None when no cert.

    The fingerprint is always computed when a cert is present; the CN is
    best-effort (None when the subject can't be parsed).
    """
    der = _extract_peer_der(scope)
    if der is None:
        return None
    return PeerCert(
        sha256=hashlib.sha256(der).hexdigest().lower(),
        cn=_cn_from_der(der),
    )


def extract_peer_fingerprint(scope: MutableMapping[str, Any]) -> Optional[str]:
    """Convenience: just the lowercase hex SHA-256 of the peer cert, or None."""
    der = _extract_peer_der(scope)
    if der is None:
        return None
    return hashlib.sha256(der).hexdigest().lower()


def _client_is_loopback(request: Request) -> bool:
    """True iff the request originated from the master box's loopback."""
    client = getattr(request, "client", None)
    host = getattr(client, "host", None) if client is not None else None
    return host in LOOPBACK_HOSTS


def require_operator_cert(request: Request) -> PeerCert:
    """FastAPI dependency authorizing a swarm control-plane operation.

    Two accepted paths, matching the deployment posture:

    * **mTLS on** (any routable bind — enforced by the swarmctl startup guard):
      a peer cert is present. Transport already proved it is CA-signed; we
      additionally require its CN to be in :data:`OPERATOR_CNS`. Worker and
      ``updater@*`` certs are rejected — a worker's still-valid cert must never
      drive enroll/deploy/teardown.
    * **Loopback plaintext** (single-host master, the shipping default): no peer
      cert, but the request came from ``127.0.0.1``/``::1``. Accepted as the
      local operator — the same trust boundary as ``docker.sock``.

    A certless request from any non-loopback client is refused (fail-closed);
    in practice the startup guard prevents that combination from arising.
    """
    peer = extract_peer_cert(request.scope)
    if peer is not None:
        if peer.cn not in OPERATOR_CNS:
            log.warning("rejected non-operator cert on control plane: cn=%r", peer.cn)
            raise HTTPException(status_code=403, detail="operator certificate required")
        return peer
    if _client_is_loopback(request):
        # Local operator on the master box; no client cert over plaintext loopback.
        return PeerCert(sha256="", cn=None)
    raise HTTPException(status_code=403, detail="operator certificate required")
