# SPDX-License-Identifier: AGPL-3.0-or-later
"""Stealth-egress httpx.AsyncClient factory.

Per the project's stealth posture, outbound calls to *third-party*
services (threat-intel providers, public APIs) MUST NOT advertise
"DECNET" in their User-Agent or other request fingerprints — operators
running honeypots want their reconnaissance dependencies to look like
generic infra, not like a tagged tool.

Canonical helper for any future module that needs to call a public API
without leaking the DECNET label. Internal calls (worker → operator's
own SIEM via webhook, swarm agent → master) deliberately keep
DECNET-tagged user-agents because the recipient wants the audit trail —
do NOT route those through this client.

Usage::

    from decnet.net.http import stealth_client

    async with stealth_client() as client:
        resp = await client.get("https://api.greynoise.io/v3/community/1.2.3.4")

The chosen UA mimics ``curl`` because it's the single most common
"non-browser, non-named-tool" UA on the public internet — anti-bot
filters routinely permit it, and an attacker who got a peek at our
egress wouldn't learn anything more specific than "something used curl".
"""
from __future__ import annotations

from typing import Optional

import httpx

# Pinned to a recent-but-not-bleeding-edge curl release. Bump on the
# normal cadence; anything in-distribution is fine. Keep this string as
# the single source of truth so future stealth helpers (browser-shaped,
# Go-shaped) live as siblings, not divergent constants.
DEFAULT_STEALTH_USER_AGENT: str = "curl/7.88.1"


def stealth_client(
    *,
    timeout: float = 10.0,
    user_agent: Optional[str] = None,
    follow_redirects: bool = False,
) -> httpx.AsyncClient:
    """Return an httpx.AsyncClient with a generic stealth User-Agent.

    Returns a fresh client per call — callers own the lifecycle and
    SHOULD use ``async with`` to ensure connection-pool teardown.

    ``follow_redirects`` defaults to ``False`` because most threat-intel
    APIs return canonical URLs and a redirect typically signals an auth
    or path mistake we'd rather surface than chase.
    """
    return httpx.AsyncClient(
        headers={"User-Agent": user_agent or DEFAULT_STEALTH_USER_AGENT},
        timeout=timeout,
        follow_redirects=follow_redirects,
    )
