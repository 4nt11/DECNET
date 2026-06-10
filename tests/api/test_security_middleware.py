# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Security-middleware tests covering:
  - V13.1.4: CORS wildcard guard raises ValueError at app startup
  - V13.1.5: Content-Type enforcement middleware (415 on wrong CT; pass for
             application/json; multipart exempt paths; GET/DELETE unaffected)
  - BUG-17:  SSE stream error log uses user["uuid"], not last_event_id
  - Regression: multipart upload endpoints still work (canary blob, file-drop)
"""
from __future__ import annotations

import pytest
import httpx


# ---------------------------------------------------------------------------
# V13.1.4 — CORS wildcard guard (unit tests; lifespan path in tests/web/)
# ---------------------------------------------------------------------------

class TestCORSWildcardGuard:
    def test_wildcard_raises(self):
        """_check_cors_origins raises ValueError when '*' is present."""
        from decnet.web.api import _check_cors_origins
        with pytest.raises(ValueError, match="wildcard"):
            _check_cors_origins(["*"])

    def test_wildcard_among_explicit_origins_raises(self):
        """Wildcard in a mixed list is still rejected."""
        from decnet.web.api import _check_cors_origins
        with pytest.raises(ValueError, match="wildcard"):
            _check_cors_origins(["https://example.com", "*"])

    def test_explicit_origins_ok(self):
        """Explicit origin URLs pass without raising."""
        from decnet.web.api import _check_cors_origins
        _check_cors_origins(["https://example.com", "https://app.internal"])

    def test_empty_origins_ok(self):
        """Empty list is valid (no CORS)."""
        from decnet.web.api import _check_cors_origins
        _check_cors_origins([])


# ---------------------------------------------------------------------------
# V13.1.5 — Content-Type enforcement middleware
# ---------------------------------------------------------------------------

class TestContentTypeMiddleware:
    @pytest.mark.asyncio
    async def test_post_wrong_content_type_returns_415(
        self, client: httpx.AsyncClient
    ):
        """POST with text/plain body to a JSON endpoint returns 415.

        /api/v1/auth/login is the most stable JSON POST target — no auth
        required, always present, middleware fires before the handler.
        """
        resp = await client.post(
            "/api/v1/auth/login",
            content=b"not json",
            headers={"Content-Type": "text/plain"},
        )
        assert resp.status_code == 415

    @pytest.mark.asyncio
    async def test_post_application_json_passes_middleware(
        self, client: httpx.AsyncClient
    ):
        """POST with application/json does NOT get a 415 from middleware."""
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "wrong"},
        )
        # Middleware passes; handler may 401/422 but must not 415.
        assert resp.status_code != 415

    @pytest.mark.asyncio
    async def test_post_json_with_charset_passes(
        self, client: httpx.AsyncClient
    ):
        """application/json; charset=utf-8 is a valid Content-Type."""
        resp = await client.post(
            "/api/v1/auth/login",
            content=b'{"username":"x","password":"y"}',
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        assert resp.status_code != 415

    @pytest.mark.asyncio
    async def test_get_not_enforced(self, client: httpx.AsyncClient, auth_token: str):
        """GET requests are never rejected by the CT middleware."""
        resp = await client.get(
            "/api/v1/logs",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp.status_code != 415

    @pytest.mark.asyncio
    async def test_delete_not_enforced(
        self, client: httpx.AsyncClient, auth_token: str
    ):
        """DELETE requests are never rejected by the CT middleware."""
        resp = await client.delete(
            "/api/v1/deckies/nonexistent",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        # Could be 404/401/403 but never 415.
        assert resp.status_code != 415

    @pytest.mark.asyncio
    async def test_multipart_canary_blob_exempt(
        self, client: httpx.AsyncClient, auth_token: str
    ):
        """Canary blob upload (multipart/form-data) is NOT rejected with 415."""
        resp = await client.post(
            "/api/v1/canary/blobs",
            files={"file": ("test.txt", b"hello world", "text/plain")},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        # 201 on success, 4xx on business-logic errors — never 415.
        assert resp.status_code != 415

    @pytest.mark.asyncio
    async def test_multipart_file_drop_exempt(
        self, client: httpx.AsyncClient, auth_token: str
    ):
        """Decky file-drop (multipart/form-data) is NOT rejected with 415."""
        resp = await client.post(
            "/api/v1/deckies/files/some-container",
            files={"file": ("test.txt", b"data", "text/plain")},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        # Expect 4xx business error (no real container), never 415.
        assert resp.status_code != 415

    @pytest.mark.asyncio
    async def test_empty_body_post_not_enforced(
        self, client: httpx.AsyncClient, auth_token: str
    ):
        """POST with genuinely empty body (Content-Length: 0) is not rejected."""
        resp = await client.post(
            "/api/v1/logs",
            content=b"",
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Content-Length": "0",
            },
        )
        # Middleware should not 415 on empty bodies.
        assert resp.status_code != 415


# ---------------------------------------------------------------------------
# BUG-17 — SSE error log uses user["uuid"], not last_event_id
# ---------------------------------------------------------------------------

class TestSSEErrorLog:
    def test_sse_error_log_uses_user_uuid(self):
        """
        Verify the log.exception call in the SSE generator uses user["uuid"],
        not last_event_id (which is an int cursor, not an identity).
        """
        import ast, pathlib
        src = pathlib.Path(
            "decnet/web/router/stream/api_stream_events.py"
        ).read_text()
        tree = ast.parse(src)

        bad_pattern_found = False
        correct_pattern_found = False

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Look for log.exception(...) calls
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "exception"):
                continue
            # Check args after the format string
            if len(node.args) >= 2:
                arg = node.args[1]
                # Bad pattern: bare Name "last_event_id"
                if isinstance(arg, ast.Name) and arg.id == "last_event_id":
                    bad_pattern_found = True
                # Good pattern: user["uuid"] subscript
                if (
                    isinstance(arg, ast.Subscript)
                    and isinstance(arg.value, ast.Name)
                    and arg.value.id == "user"
                ):
                    correct_pattern_found = True

        assert not bad_pattern_found, (
            "BUG-17: log.exception still uses last_event_id instead of user['uuid']"
        )
        assert correct_pattern_found, (
            "BUG-17 fix not found: expected log.exception(..., user['uuid']) in SSE handler"
        )

    @pytest.mark.asyncio
    async def test_sse_stream_unauthenticated_401(self, client: httpx.AsyncClient):
        """SSE endpoint rejects unauthenticated requests (regression guard)."""
        resp = await client.get("/api/v1/stream")
        assert resp.status_code == 401
