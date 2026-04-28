"""OpenAPI must advertise 429 on every operation.

SlowAPI can return 429 from any rate-limited route at any time. If the
schema doesn't list it, schemathesis (and any other contract-driven
client) treats a legitimate rate-limit response as a contract violation.
"""
from decnet.web.api import app


def test_every_operation_documents_429() -> None:
    schema = app.openapi()
    paths = schema.get("paths", {})
    assert paths, "OpenAPI schema is empty — router not mounted"

    http_methods = {"get", "post", "put", "patch", "delete", "options", "head"}
    missing: list[str] = []
    for path, item in paths.items():
        for method, op in item.items():
            if method.lower() not in http_methods:
                continue
            if "429" not in op.get("responses", {}):
                missing.append(f"{method.upper()} {path}")

    assert not missing, f"Operations missing 429 response: {missing[:5]}"
