# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rate-limiting infra for the dashboard API.

Uses slowapi (which wraps the `limits` library) with in-memory storage.
In-memory is intentional for v1:

- The dashboard API runs on a single process per host (the `decnet api`
  worker). Swarm agents do not serve the dashboard; there is no need for
  cross-process shared state.
- Adding Redis as a hard dependency of the master for this one feature
  is disproportionate.

Trust boundary note: `get_remote_address` uses `request.client.host`,
i.e. the TCP peer's IP. We deliberately do NOT trust `X-Forwarded-For`
because it is trivially spoofable by any client. Operators running
DECNET behind a reverse proxy get one shared bucket for the whole proxy
— that is an accepted limitation recorded in the threat model
(see `development/THREAT_MODEL.md` §Dashboard↔API, DA-08). Revisit when
we introduce a verified-proxy config.
"""
from __future__ import annotations

import json
import os
from typing import Any, Awaitable, Callable

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def _limiter_enabled() -> bool:
    """``DECNET_LIMITER_ENABLED=false`` disables the limiter process-wide.

    Intended for stress / load testing, where a single Locust host
    represents thousands of virtual users but shares one source IP and
    one admin username — the real-world limits (10/5min per IP, per
    user) would otherwise cap every run at 10 successful logins. The
    default is ``true``; nobody should ever ship a release with this
    off.
    """
    return os.environ.get("DECNET_LIMITER_ENABLED", "true").lower() != "false"


# Single process-wide limiter. Importing modules pull this instance to
# apply `@limiter.limit(...)` decorators on their routes. Default
# headers off: FastAPI response_model handlers return dicts, not
# Starlette Response objects, and slowapi's header injection only
# supports the latter. Legit clients can back off on their own from
# the 429 body; attackers ignore Retry-After anyway.
limiter: Limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    enabled=_limiter_enabled(),
)


def login_ip_key(request: Request) -> str:
    """Per-IP bucket key for the login endpoint.

    Thin wrapper around slowapi's default so tests can monkey-patch this
    module attribute without reaching into slowapi internals.
    """
    return f"login-ip:{get_remote_address(request)}"


async def login_username_key(request: Request) -> str:
    """Per-username bucket key for the login endpoint.

    Reads the request body to extract the claimed username. The body is
    cached by Starlette, so FastAPI's subsequent Pydantic parsing still
    sees the same bytes. Malformed bodies all collapse to a single
    bucket — that is intentional; garbage traffic gets throttled as one
    bad actor rather than offered an escape hatch.
    """
    try:
        body: bytes = await request.body()
        data: Any = json.loads(body or b"{}")
        username = data.get("username") if isinstance(data, dict) else None
        if isinstance(username, str) and username:
            return f"login-user:{username}"
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        pass
    return "login-user:__unparseable__"


# Exported so tests can monkey-patch a synchronous counterpart if they
# need deterministic keys without parsing bodies.
LoginKeyFunc = Callable[[Request], Awaitable[str] | str]
