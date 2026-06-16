# SPDX-License-Identifier: AGPL-3.0-or-later
"""BUG-2 regression: post-deploy reconcile must NOT mark generator-named
deckies (``decky-NNN``) as ``failed`` when their containers are running.

Root cause: the OLD heuristic ``"-" not in service_name`` never fires for
generator-named deckies because those names always contain a hyphen.  The fix
replaces the heuristic with explicit set-membership against
``expected_decky_names`` built from ``hydrated['deckies']``.

These tests exercise the REAL production code path:
``decnet.engine.deployer.deploy_topology``.  They mock every external I/O
boundary (Docker, compose, repo, filesystem) at the same layer used by the
rest of the deploy test-suite, so the assertions flow through the actual
``expected_decky_names`` / ``decky_state_by_name`` logic in deployer.py.
A revert of the BUG-2 fix causes both primary tests to FAIL (red-before /
green-after verified manually — see docstring on each test).
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_decky(name: str, *, uuid_val: str | None = None) -> dict[str, Any]:
    return {
        "uuid": uuid_val or str(uuid.uuid4()),
        "name": name,
        "decky_config": {"name": name},
    }


def _ps_rows(decky_name: str, *service_suffixes: str, state: str = "running") -> list[dict]:
    """Simulate ``docker compose ps`` JSON rows for one decky + its services."""
    rows: list[dict] = [
        {"Service": decky_name, "Name": decky_name, "State": state, "ExitCode": 0},
    ]
    for svc in service_suffixes:
        container = f"{decky_name}-{svc}"
        rows.append({"Service": container, "Name": container, "State": state, "ExitCode": 0})
    return rows


def _build_hydrated(deckies: list[dict[str, Any]]) -> dict[str, Any]:
    """Minimal hydrated topology dict that satisfies deploy_topology's lookups."""
    return {
        "topology": {
            "uuid": "topo-test-1234",
            # No target_host_uuid → master-local deploy path
        },
        "lans": [
            {
                "name": "DMZ",
                "subnet": "10.99.0.0/24",
                "is_dmz": True,
            }
        ],
        "deckies": deckies,
    }


async def _run_deploy(hydrated: dict, ps_rows: list[dict]) -> dict[str, str]:
    """Drive deploy_topology with full I/O mocks; return the state values
    passed to ``repo.update_topology_decky`` keyed by decky UUID."""
    from decnet.engine import deployer as _dep

    topology_id = hydrated["topology"]["uuid"]
    recorded: dict[str, str] = {}

    repo = MagicMock()
    repo.update_topology_decky = AsyncMock(side_effect=lambda uid, patch: recorded.__setitem__(uid, patch["state"]))

    # Map uuid → name so we can translate the assertion later
    uuid_to_name = {d["uuid"]: d["name"] for d in hydrated["deckies"]}

    with (
        patch.object(_dep, "hydrate", new=AsyncMock(return_value=hydrated)),
        patch.object(_dep, "_validate_topology", return_value={}),
        patch.object(_dep, "_validation_errors", return_value=False),
        patch.object(_dep, "check_no_host_port_collision", return_value=[]),
        patch.object(_dep, "_warn_if_userland_proxy_enabled"),
        patch.object(_dep, "transition_status", new=AsyncMock()),
        # _topology_compose_path must return a Path; compose_path.exists()
        # is checked in the rollback guard — return a path that does NOT exist
        # so the rollback branch is skipped.
        patch.object(_dep, "_topology_compose_path", return_value=Path("/nonexistent/compose.yml")),
        patch.object(_dep, "_topology_compose_project", return_value="test-project"),
        patch.object(_dep, "create_bridge_network"),
        patch.object(_dep, "write_topology_compose"),
        # _compose_with_retry is called inside anyio.to_thread.run_sync(lambda: ...)
        # We patch it so the lambda is a no-op.
        patch.object(_dep, "_compose_with_retry"),
        # _compose_ps is also called inside anyio.to_thread.run_sync; patch it
        # to return our controlled rows.
        patch.object(_dep, "_compose_ps", return_value=ps_rows),
        # docker.from_env() is called at deploy time
        patch("decnet.engine.deployer.docker") as mock_docker,
        # Silence the canary planter import that runs at the end
        patch.dict("sys.modules", {"decnet.canary": MagicMock(), "decnet.canary.planter": MagicMock()}),
    ):
        mock_docker.from_env.return_value = MagicMock()
        await _dep.deploy_topology(repo, topology_id)

    # Translate uuid keys → decky names for readable assertions
    return {uuid_to_name[uid]: state for uid, state in recorded.items()}


# ── BUG-2 primary regression tests ───────────────────────────────────────────

@pytest.mark.anyio
async def test_generator_named_decky_reconciles_running() -> None:
    """BUG-2 primary: generator-named decky whose container is RUNNING must be
    reconciled to state='running', NOT 'failed'.

    RED before fix: the old ``"-" not in service_name`` heuristic never cached
    "decky-001" (contains a hyphen), so ``decky_state_by_name.get("decky-001")``
    returned ``"unknown"`` and new_state was forced to ``"failed"``.
    GREEN after fix: membership check against expected_decky_names finds
    "decky-001" and correctly stores state="running".
    """
    decky = _make_decky("decky-001")
    hydrated = _build_hydrated([decky])
    ps = _ps_rows("decky-001", "ssh", "http")  # base + two service containers

    result = await _run_deploy(hydrated, ps)

    assert result["decky-001"] == "running", (
        "Generator-named decky with running container must reconcile to 'running'"
    )


@pytest.mark.anyio
async def test_absent_decky_reconciles_failed() -> None:
    """Genuinely absent / stopped decky must reconcile to state='failed'.

    This covers the other branch: if no ps row matches the decky name
    (container never started or exited), new_state must be 'failed'.
    GREEN in both old and new code — ensures the 'failed' path is not broken
    by the BUG-2 fix.
    """
    decky = _make_decky("decky-002")
    hydrated = _build_hydrated([decky])
    # ps rows contain nothing for decky-002 — simulates a decky that never started
    ps: list[dict] = []

    result = await _run_deploy(hydrated, ps)

    assert result["decky-002"] == "failed", (
        "Decky with no running container must reconcile to 'failed'"
    )


@pytest.mark.anyio
async def test_both_branches_in_one_topology() -> None:
    """Running generator-named decky → 'running'; absent decky → 'failed'.

    Exercises both branches of the reconcile loop simultaneously, which
    is the most direct regression guard: if the fix is reverted, decky-001
    flips to 'failed' while decky-002 stays 'failed', making the first
    assertion fail.
    """
    decky_running = _make_decky("decky-001")
    decky_absent = _make_decky("decky-099")
    hydrated = _build_hydrated([decky_running, decky_absent])

    # Only decky-001 has running containers; decky-099 has none
    ps = _ps_rows("decky-001", "ssh")

    result = await _run_deploy(hydrated, ps)

    assert result["decky-001"] == "running", (
        "Running generator-named decky must not be marked failed"
    )
    assert result["decky-099"] == "failed", (
        "Absent decky must be marked failed"
    )


@pytest.mark.anyio
async def test_decky_config_nested_name_is_honoured() -> None:
    """When decky_config.name differs from outer name, the config name is
    used for both compose service lookup and repo update — same logic as
    deployer.py lines 1101-1104 and 1136-1138."""
    outer_name = "old-outer-name"
    config_name = "decky-007"
    uid = str(uuid.uuid4())
    decky = {
        "uuid": uid,
        "name": outer_name,
        "decky_config": {"name": config_name},
    }
    hydrated = _build_hydrated([decky])
    ps = _ps_rows(config_name, "ssh")

    from decnet.engine import deployer as _dep
    from unittest.mock import AsyncMock, MagicMock, patch

    recorded: dict[str, str] = {}
    repo = MagicMock()
    repo.update_topology_decky = AsyncMock(
        side_effect=lambda u, p: recorded.__setitem__(u, p["state"])
    )

    topology_id = hydrated["topology"]["uuid"]

    with (
        patch.object(_dep, "hydrate", new=AsyncMock(return_value=hydrated)),
        patch.object(_dep, "_validate_topology", return_value={}),
        patch.object(_dep, "_validation_errors", return_value=False),
        patch.object(_dep, "check_no_host_port_collision", return_value=[]),
        patch.object(_dep, "_warn_if_userland_proxy_enabled"),
        patch.object(_dep, "transition_status", new=AsyncMock()),
        patch.object(_dep, "_topology_compose_path", return_value=Path("/nonexistent/compose.yml")),
        patch.object(_dep, "_topology_compose_project", return_value="test-project"),
        patch.object(_dep, "create_bridge_network"),
        patch.object(_dep, "write_topology_compose"),
        patch.object(_dep, "_compose_with_retry"),
        patch.object(_dep, "_compose_ps", return_value=ps),
        patch("decnet.engine.deployer.docker") as mock_docker,
        patch.dict("sys.modules", {"decnet.canary": MagicMock(), "decnet.canary.planter": MagicMock()}),
    ):
        mock_docker.from_env.return_value = MagicMock()
        await _dep.deploy_topology(repo, topology_id)

    assert recorded.get(uid) == "running", (
        "decky_config.name must be used for ps lookup; decky should reconcile running"
    )
