# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Open-core tier seams: the Professional tier is a separate private repo mounted at
decnet/pro/ (git-ignored here) that contributes to several core surfaces, each
wired only when the package is present:

* decnet/pro/services/ — advanced honeypots, discovered by the service registry.
* decnet/pro/routes.py  — ROUTERS, mounted under /api/v1 by the web router.

Absence of decnet/pro/ is the entitlement gate; there is no licence check.

One test function on purpose: it mutates decnet/pro/services/, the process-global
service registry, and reloads decnet.web.router — doing that sequentially in one
worker avoids the xdist races that separate tests on shared state would hit.
"""

import gc
import importlib
import sys
from pathlib import Path

import decnet.services.registry as reg

_DEMO_MOD = "_demo_pro_tier_test"
_DEMO_NAME = "demo-pro-honeypot"


def _reload_registry():
    reg._loaded = False
    reg._registry.clear()
    reg._load_plugins()


def test_pro_tier_seams():
    # --- service-discovery seam -------------------------------------------
    services_dir = Path(reg.__file__).parent.parent / "pro" / "services"
    demo = services_dir / f"{_DEMO_MOD}.py"
    created_dir = not services_dir.exists()
    if created_dir:
        services_dir.mkdir(parents=True)
        (services_dir / "__init__.py").write_text("")

    try:
        _reload_registry()
        assert _DEMO_NAME not in reg.all_services()  # gate closed
        assert "ssh" in reg.all_services()            # community untouched

        # A pro honeypot that EXTENDS a community service — only reachable via
        # the registry's recursive subclass walk.
        demo.write_text(
            "from decnet.services.ssh import SSHService\n"
            "class DemoProHoneypot(SSHService):\n"
            f"    name = {_DEMO_NAME!r}\n"
        )
        _reload_registry()
        assert _DEMO_NAME in reg.all_services()
    finally:
        demo.unlink(missing_ok=True)
        if created_dir:
            import shutil
            shutil.rmtree(services_dir)
        sys.modules.pop(f"decnet.pro.services.{_DEMO_MOD}", None)
        gc.collect()
        _reload_registry()

    # --- API-router seam --------------------------------------------------
    import decnet.pro.routes as pro_routes
    import decnet.web.router as web_router
    from fastapi import APIRouter, FastAPI

    saved = pro_routes.ROUTERS
    probe = APIRouter()

    @probe.get("/pro/_probe_test")
    async def _probe():  # pragma: no cover - never called, just registered
        return {}

    try:
        pro_routes.ROUTERS = [probe]
        importlib.reload(web_router)
        # This FastAPI version defers route flattening (_IncludedRouter), so go
        # through openapi() — it forces resolution and lists effective paths.
        app = FastAPI()
        app.include_router(web_router.api_router, prefix="/api/v1")
        assert "/api/v1/pro/_probe_test" in app.openapi()["paths"]
    finally:
        pro_routes.ROUTERS = saved
        importlib.reload(web_router)  # rebuild a pro-free api_router for others


def test_pro_cli_registered_when_mounted():
    """When decnet/pro/ is mounted, its CLI modules' commands join the root app.

    Read-only against the already-built decnet.cli.app — no reload, no fs
    mutation. Skips on the Community build, where decnet.pro is absent."""
    import importlib.util

    if importlib.util.find_spec("decnet.pro.cli") is None:
        import pytest

        pytest.skip("decnet.pro not mounted (community build)")

    import decnet.cli as cli

    group_names = {g.name for g in cli.app.registered_groups}
    assert "pro-intel" in group_names  # shipped example pro daemon group
