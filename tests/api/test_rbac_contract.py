# SPDX-License-Identifier: AGPL-3.0-or-later
"""
RBAC contract test — every route is classified by server-side dependency
introspection and exercised with a viewer JWT.

Covers THREAT_MODEL.md F2/E (mutation bypass via missing `require_admin`)
and F5/E (mutation routes returning 403 for viewer). The 401-unauth half
is covered by `test_schemathesis.py::test_auth_enforcement`.

We deliberately do NOT annotate role hints in the OpenAPI spec —
classification stays server-side so an attacker reading /openapi.json
can't enumerate admin routes.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.routing import APIRoute

from decnet.web.api import app
from decnet.web.dependencies import (
    require_admin,
    require_viewer,
    require_stream_viewer,
    get_current_user_unchecked,
    get_current_user,
)


# ---------------------------------------------------------------------------
# Route classification (runs at import time)
# ---------------------------------------------------------------------------

_ADMIN_CALLS = {require_admin}
_VIEWER_CALLS = {require_viewer, require_stream_viewer, get_current_user_unchecked, get_current_user}


def _walk_deps(dependant) -> set:
    """Recursively collect every dependency `call` in the tree."""
    calls: set = set()
    stack = list(dependant.dependencies)
    while stack:
        d = stack.pop()
        if d.call is not None:
            calls.add(d.call)
        stack.extend(d.dependencies)
    return calls


def _classify(route: APIRoute) -> str:
    calls = _walk_deps(route.dependant)
    if calls & _ADMIN_CALLS:
        return "admin"
    if calls & _VIEWER_CALLS:
        return "viewer"
    return "open"


def _is_sse(route: APIRoute) -> bool:
    """SSE endpoints keep the connection open — authz fires before the stream
    starts, but httpx won't return until the server closes. Skip them here;
    F6 gets its own dedicated verification pass."""
    return route.path.endswith(("/events", "/stream", "/status-events"))


def _collect() -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    """Return (admin_routes, viewer_routes) as (method, path, name) triples."""
    admin: list[tuple[str, str, str]] = []
    viewer: list[tuple[str, str, str]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if _is_sse(route):
            continue
        cls = _classify(route)
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            entry = (method, route.path, route.name)
            if cls == "admin":
                admin.append(entry)
            elif cls == "viewer":
                viewer.append(entry)
    return admin, viewer


ADMIN_ROUTES, VIEWER_ROUTES = _collect()

assert ADMIN_ROUTES, "no admin routes discovered — classifier is broken"
assert VIEWER_ROUTES, "no viewer routes discovered — classifier is broken"


# ---------------------------------------------------------------------------
# Path-param substitution
# ---------------------------------------------------------------------------

_ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def _substitute_path(path: str, route: APIRoute) -> str:
    """Fill `{param}` placeholders with dummy values that satisfy path regex.

    Authz (403) fires before route-handler execution, so the values don't
    need to match real DB rows — they only need to survive FastAPI's
    param-type coercion. Heuristic by param name keeps this independent
    of pydantic-version internals.
    """
    out = path
    while "{" in out:
        start = out.index("{")
        end = out.index("}", start)
        name = out[start + 1 : end].lower()
        if "uuid" in name:
            value = _ZERO_UUID
        elif name.endswith("_id") or name == "id":
            value = "1"
        else:
            value = "x"
        out = out[:start] + value + out[end + 1 :]
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@pytest.mark.parametrize(
    "method,path,name",
    ADMIN_ROUTES,
    ids=lambda t: f"{t[0]} {t[1]}" if isinstance(t, tuple) else str(t),
)
async def test_admin_route_rejects_viewer(client, viewer_token, method, path, name):
    """Every admin-classified route must return 403 when hit with a viewer JWT.

    If a route returns 422 instead, the `Depends(require_admin)` parameter
    is declared after a body/query param in the route signature — move it
    earlier so authz runs before schema validation. A 401 means the token
    was rejected outright (viewer user seeding broken → check conftest).
    """
    url = _substitute_path(path, _route_lookup(method, path))
    kwargs = {"headers": {"Authorization": f"Bearer {viewer_token}"}}
    if method in _WRITE_METHODS:
        kwargs["json"] = {}
    resp = await client.request(method, url, **kwargs)
    assert resp.status_code == 403, (
        f"{method} {path} (name={name}): expected 403 for viewer, "
        f"got {resp.status_code} — body={resp.text[:200]!r}. "
        "If 422: move Depends(require_admin) before the body param in the signature. "
        "If 401: viewer token invalid."
    )


@pytest.mark.parametrize(
    "method,path,name",
    VIEWER_ROUTES,
    ids=lambda t: f"{t[0]} {t[1]}" if isinstance(t, tuple) else str(t),
)
async def test_viewer_route_does_not_reject_viewer(client, viewer_token, method, path, name):
    """Viewer-accessible routes must not return 401/403 for a valid viewer JWT."""
    url = _substitute_path(path, _route_lookup(method, path))
    kwargs = {"headers": {"Authorization": f"Bearer {viewer_token}"}}
    if method in _WRITE_METHODS:
        kwargs["json"] = {}
    resp = await client.request(method, url, **kwargs)
    assert resp.status_code not in (401, 403), (
        f"{method} {path} (name={name}): viewer unexpectedly got {resp.status_code} "
        f"— body={resp.text[:200]!r}"
    )


def _route_lookup(method: str, path: str) -> APIRoute:
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == path and method in route.methods:
            return route
    raise LookupError(f"{method} {path}")
