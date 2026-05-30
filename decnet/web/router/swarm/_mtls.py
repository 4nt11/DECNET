# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator authorization for the swarm control plane.

The transport peer-identity primitives live in :mod:`decnet.web._mtls` so the
minimal worker-side updater can reuse them without importing the API router
tree. This module adds the swarm-controller-specific operator gate on top and
re-exports the primitives for existing importers.

Role distinction is by CN, which the PKI assigns per identity
(``decnet/swarm/pki.py:issue_worker_cert``):

    decnet-master        master / operator client
    swarmctl             operator CLI server identity
    {agent_name}         worker agent
    updater@{agent_name} per-worker updater
"""
from __future__ import annotations

from fastapi import HTTPException, Request

from decnet.logging import get_logger
from decnet.web._mtls import (  # re-exported for existing importers
    LOOPBACK_HOSTS,
    PeerCert,
    client_is_loopback,
    extract_peer_cert,
    extract_peer_fingerprint,
)

__all__ = [
    "LOOPBACK_HOSTS",
    "PeerCert",
    "client_is_loopback",
    "extract_peer_cert",
    "extract_peer_fingerprint",
    "OPERATOR_CNS",
    "require_operator_cert",
]

log = get_logger("swarm.mtls")

# Operator identities permitted to drive the control plane (enroll / deploy /
# teardown / host management).  Worker and updater certs are intentionally
# excluded — a worker's still-valid cert must not be able to enroll new hosts
# or tear the fleet down.
OPERATOR_CNS = frozenset({"decnet-master", "swarmctl"})


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
    if client_is_loopback(request):
        # Local operator on the master box; no client cert over plaintext loopback.
        return PeerCert(sha256="", cn=None)
    raise HTTPException(status_code=403, detail="operator certificate required")
