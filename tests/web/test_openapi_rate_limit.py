"""OpenAPI must advertise 429 on every slowapi-rate-limited operation.

Other endpoints may also advertise 429 for their own reasons (e.g. the
SSE connection cap in ``decnet.web.sse_limits``); the test does not
forbid those — it only enforces the slowapi side.
"""
from decnet.web.api import app, _rate_limited_endpoint_names
from fastapi.routing import APIRoute


def _route_qualname_index() -> dict[tuple[str, str], str]:
    idx: dict[tuple[str, str], str] = {}
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        qn = f"{route.endpoint.__module__}.{route.endpoint.__name__}"
        for method in route.methods or ():
            idx[(route.path, method.lower())] = qn
    return idx


def test_429_documented_on_rate_limited_endpoints_only() -> None:
    schema = app.openapi()
    paths = schema.get("paths", {})
    assert paths, "OpenAPI schema is empty — router not mounted"

    rate_limited = _rate_limited_endpoint_names()
    assert rate_limited, "no @limiter.limit-decorated endpoints found"

    qualname_for = _route_qualname_index()

    http_methods = {"get", "post", "put", "patch", "delete", "options", "head"}
    missing: list[str] = []

    for path, item in paths.items():
        for method, op in item.items():
            if method.lower() not in http_methods:
                continue
            qn = qualname_for.get((path, method.lower()))
            if qn in rate_limited and "429" not in op.get("responses", {}):
                missing.append(f"{method.upper()} {path}")

    assert not missing, f"rate-limited ops missing 429: {missing}"


def test_login_endpoint_documents_429() -> None:
    """Sanity check the one endpoint we know is rate-limited."""
    schema = app.openapi()
    op = schema["paths"]["/api/v1/auth/login"]["post"]
    assert "429" in op["responses"]
