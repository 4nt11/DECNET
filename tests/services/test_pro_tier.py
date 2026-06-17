# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Open-core tier split: the Professional build supplies advanced honeypots via the
optional decnet/services/pro/ subpackage (a separate private repo cloned into
this path; git-ignored here so it never enters the open-core tree). The
Community build simply omits it.

The registry must auto-discover pro honeypots when present — including ones that
EXTEND a community service rather than subclassing BaseService directly (the
recursive-subclass walk). Absence of a pro module is the entitlement gate; there
is no licence check.

One test on purpose: it mutates decnet/services/pro/ and the process-global
registry, so it cannot race a sibling test under xdist. It tolerates a pro/ dir
that already exists (developer tree) and leaves the registry pristine.
"""

import gc
import shutil
import sys
from pathlib import Path

import decnet.services.registry as reg

_DEMO_MOD = "_demo_pro_tier_test"
_DEMO_NAME = "demo-pro-honeypot"


def _reload_clean():
    reg._loaded = False
    reg._registry.clear()
    reg._load_plugins()


def test_pro_tier_packaging_gate():
    pkg_dir = Path(reg.__file__).parent
    pro_dir = pkg_dir / "pro"
    init = pro_dir / "__init__.py"
    demo = pro_dir / f"{_DEMO_MOD}.py"

    created_dir = not pro_dir.exists()
    if created_dir:
        pro_dir.mkdir()
    created_init = not init.exists()
    if created_init:
        init.write_text("")

    try:
        # Gate closed: our pro honeypot absent, community services present.
        _reload_clean()
        assert _DEMO_NAME not in reg.all_services()
        assert "ssh" in reg.all_services()

        # Professional build: drop in a pro honeypot that EXTENDS a community
        # service (only reachable via the recursive subclass walk).
        demo.write_text(
            "from decnet.services.ssh import SSHService\n"
            "class DemoProHoneypot(SSHService):\n"
            f"    name = {_DEMO_NAME!r}\n"
        )
        _reload_clean()
        svcs = reg.all_services()
        assert _DEMO_NAME in svcs  # pro discovered
        assert "ssh" in svcs       # community untouched
    finally:
        demo.unlink(missing_ok=True)
        if created_init:
            init.unlink(missing_ok=True)
        if created_dir:
            shutil.rmtree(pro_dir)
        # Drop the dynamically-imported class so it can't pollute the registry
        # for sibling tests sharing this worker.
        sys.modules.pop(f"decnet.services.pro.{_DEMO_MOD}", None)
        gc.collect()
        _reload_clean()
