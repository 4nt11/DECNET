# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import os

from fastapi import APIRouter, Depends, HTTPException, status

from decnet.bus.factory import get_bus
from decnet.lifecycle.runner import run_deploy
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.config import DEFAULT_MUTATE_INTERVAL, DecnetConfig, DeckyConfig, _ROOT
from decnet.ini_loader import load_ini_from_string
from decnet.network import detect_interface, detect_subnet, get_host_ip
from decnet.web.dependencies import require_admin, repo
from decnet.web.db.models import DeployIniRequest, DeployResponse

log = get_logger("api")

router = APIRouter()


async def _commit_fleet_to_db(deckies: list[DeckyConfig], *, replace_fleet: bool) -> None:
    """Synchronously reconcile ``fleet_deckies`` to *deckies*.

    fleet_deckies is the source of truth the deploy guard now reads
    (``existing_deckies``). Committing the intended shape here — before the
    async deploy task's engine mirror runs — means rapid sequential web
    deploys each read a current fleet (no self-wipe) and the dashboard
    observes the new shape immediately. Mirrors the payload shape of
    ``engine.deployer._mirror_fleet_deploy_to_db``.

    In replace mode, rows absent from *deckies* are deleted so the committed
    inventory matches the desired set; the async reconciler/teardown mirror
    converges the actual containers separately.
    """
    from decnet.web.db.models import LOCAL_HOST_SENTINEL

    keep = {(d.host_uuid or LOCAL_HOST_SENTINEL, d.name) for d in deckies}
    if replace_fleet:
        for row in await repo.list_fleet_deckies():
            host = row.get("host_uuid") or LOCAL_HOST_SENTINEL
            if (host, row.get("name")) not in keep:
                await repo.delete_fleet_decky(host_uuid=host, name=row["name"])
    for d in deckies:
        await repo.upsert_fleet_decky({
            "host_uuid": d.host_uuid or LOCAL_HOST_SENTINEL,
            "name": d.name,
            "services": list(d.services),
            "decky_config": d.model_dump(mode="json"),
            "decky_ip": d.ip,
            "state": "running",
        })


@router.post(
    "/deckies/deploy",
    tags=["Fleet Management"],
    status_code=status.HTTP_202_ACCEPTED,
    response_model=DeployResponse,
    responses={
        202: {"description": "Deploy accepted; poll GET /deckies/lifecycle?ids=... for terminal status"},
        400: {"description": "Bad Request (e.g. malformed JSON)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        409: {"description": "Configuration conflict (e.g. invalid IP allocation or network mismatch)"},
        422: {"description": "Invalid INI config or schema validation error"},
    }
)
@_traced("api.deploy_deckies")
async def api_deploy_deckies(req: DeployIniRequest, admin: dict = Depends(require_admin)) -> dict:
    from decnet.fleet import build_deckies_from_ini

    try:
        ini = load_ini_from_string(req.ini_content)
    except ValueError as e:
        log.debug("deploy: invalid INI structure: %s", e)
        raise HTTPException(status_code=409, detail=str(e))

    log.debug("deploy: processing configuration for %d deckies", len(ini.deckies))

    state_dict = await repo.get_state("deployment")
    ingest_log_file = os.environ.get("DECNET_INGEST_LOG_FILE")

    config: DecnetConfig | None = None
    if state_dict:
        config = DecnetConfig(**state_dict["config"])
        subnet_cidr = ini.subnet or config.subnet
        gateway = ini.gateway or config.gateway
        iface = config.interface
        host_ip = get_host_ip(iface)
        # Always sync config log_file with current API ingestion target
        if ingest_log_file:
            config.log_file = ingest_log_file
    else:
        # No state yet — infer network details from the INI or the host. We
        # defer instantiating DecnetConfig until after build_deckies_from_ini
        # because DecnetConfig.deckies has min_length=1.
        try:
            iface = ini.interface or detect_interface()
            subnet_cidr, gateway = ini.subnet or "", ini.gateway or ""
            if not subnet_cidr or not gateway:
                detected_subnet, detected_gateway = detect_subnet(iface)
                subnet_cidr = subnet_cidr or detected_subnet
                gateway = gateway or detected_gateway
            host_ip = get_host_ip(iface)
        except RuntimeError as e:
            raise HTTPException(
                status_code=409,
                detail=f"Network configuration conflict: {e}. "
                       "Add a [general] section with interface=, net=, and gw= to the INI."
            )

    # Snapshot the existing fleet (from prior state, NOT the freshly-built
    # config below) so additive collision checks compare new against prior
    # rather than against themselves. Existing IPs are passed into
    # build_deckies_from_ini as reserved so auto-allocation skips them.
    # The existing fleet comes from fleet_deckies (engine-mirrored on CLI
    # *and* web deploys), NOT from config.deckies carried by the
    # State["deployment"] key. A CLI/seed-established fleet never lands in
    # that key, so the additive collision guard ran blind and the reconciler
    # wiped the fleet — root cause of BUG-2. fleet_deckies is the store the
    # source-of-truth model (fleet/reconciler.py) names as the API's view.
    # See development/ADR-001-FLEET-SOURCE-OF-TRUTH.md.
    existing_rows = await repo.list_fleet_deckies()
    existing_deckies = [
        DeckyConfig(**r["decky_config"])
        for r in existing_rows
        if r.get("decky_config")
    ]
    reserved_ips: set[str] | None = (
        {d.ip for d in existing_deckies if d.ip}
        if not req.replace_fleet and existing_deckies
        else None
    )

    try:
        new_decky_configs = build_deckies_from_ini(
            ini, subnet_cidr, gateway, host_ip, False,
            cli_mutate_interval=None, reserved_ips=reserved_ips,
        )
    except ValueError as e:
        log.debug("deploy: build_deckies_from_ini rejected input: %s", e)
        raise HTTPException(status_code=409, detail=str(e))

    if config is None:
        config = DecnetConfig(
            mode="unihost",
            interface=iface,
            subnet=subnet_cidr,
            gateway=gateway,
            deckies=new_decky_configs,
            log_file=ingest_log_file,
            ipvlan=False,
            mutate_interval=ini.mutate_interval or DEFAULT_MUTATE_INTERVAL,
        )

    # Two intents collapse onto one endpoint:
    #
    # * replace_fleet=True (explicit): INI is the complete desired fleet.
    #   Anything absent is torn down by the reconciler. This is the path
    #   for set-desired-state callers (CLI, declarative tooling).
    # * replace_fleet=False (default, wizard path): INI is appended to the
    #   existing fleet. The wizard only POSTs the new decky and would
    #   otherwise see prior deckies silently deleted by the reconciler.
    #
    # The historical "always full replace" behaviour was added to dodge
    # stale-IP collisions on redeploy ("Address already in use"); that's
    # now scoped to replace_fleet=True.
    if req.replace_fleet:
        config.deckies = list(new_decky_configs)
    else:
        existing_names = {d.name for d in existing_deckies}
        existing_ips = {d.ip for d in existing_deckies if d.ip}
        for d in new_decky_configs:
            if d.name in existing_names:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"decky '{d.name}' already exists; "
                        "submit with replace_fleet=true to overwrite the fleet"
                    ),
                )
            if d.ip and d.ip in existing_ips:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"IP {d.ip} is already in use by an existing decky"
                    ),
                )
        config.deckies = existing_deckies + list(new_decky_configs)

    limits_state = await repo.get_state("config_limits")
    deployment_limit = limits_state.get("deployment_limit", 10) if limits_state else 10
    if len(config.deckies) > deployment_limit:
        raise HTTPException(
            status_code=409,
            detail=f"Deployment would result in {len(config.deckies)} deckies, "
                   f"exceeding the configured limit of {deployment_limit}",
        )

    # Auto-mode: if we're a master with at least one enrolled/active SWARM
    # host, shard the deckies across those workers instead of spawning docker
    # containers on the master itself. Round-robin assignment over deckies
    # that don't already carry a host_uuid (state from a prior swarm deploy
    # keeps its original assignment).
    swarm_hosts: list[dict] = []
    if os.environ.get("DECNET_MODE", "master").lower() == "master":
        swarm_hosts = [
            h for h in await repo.list_swarm_hosts()
            if h.get("status") in ("active", "enrolled") and h.get("address")
        ]

    if swarm_hosts:
        # Carry-over from a prior deployment may reference a host_uuid that's
        # since been decommissioned / re-enrolled at a new uuid. Drop any
        # assignment that isn't in the currently-reachable set, then round-
        # robin-fill the blanks — otherwise dispatch 404s on a dead uuid.
        live_uuids = {h["uuid"] for h in swarm_hosts}
        for d in config.deckies:
            if d.host_uuid and d.host_uuid not in live_uuids:
                d.host_uuid = None
        unassigned = [d for d in config.deckies if not d.host_uuid]
        for i, d in enumerate(unassigned):
            d.host_uuid = swarm_hosts[i % len(swarm_hosts)]["uuid"]
        config = config.model_copy(update={"mode": "swarm"})
        mode = "swarm"
    else:
        mode = "unihost"

    # Commit the new shape before spawning so the wizard / dashboard
    # observe the intended fleet immediately; lifecycle rows track the
    # operation's progress separately.
    new_state_payload = {
        "config": config.model_dump(),
        "compose_path": state_dict["compose_path"] if state_dict else str(
            _ROOT / "docker-compose.yml",
        ),
    }
    await repo.set_state("deployment", new_state_payload)
    # Commit the intended fleet to fleet_deckies — the store the deploy guard
    # and get_deckies() now read. set_state("deployment") above is retained
    # for the mutate handlers / mutator engine that still coordinate through
    # that key (their consolidation is tracked in the ADR, open question 7).
    await _commit_fleet_to_db(config.deckies, replace_fleet=req.replace_fleet)

    # Lifecycle rows track THIS call's deployments only. In additive mode
    # the existing deckies are already running and don't get a new
    # lifecycle row — the caller polls /deckies/lifecycle for just the
    # deckies they submitted. In replace mode every decky in the new
    # config is being (re)deployed and gets a row.
    new_names = {d.name for d in new_decky_configs}
    lifecycle_ids: dict[str, str] = {}
    for d in config.deckies:
        if not req.replace_fleet and d.name not in new_names:
            continue
        lid = await repo.create_lifecycle({
            "decky_name": d.name,
            "host_uuid": d.host_uuid,
            "operation": "deploy",
        })
        lifecycle_ids[d.name] = lid

    try:
        bus = get_bus(client_name="api.deploy")
    except Exception:
        bus = None

    if os.environ.get("DECNET_CONTRACT_TEST") != "true":
        asyncio.create_task(
            run_deploy(repo, bus, lifecycle_ids=lifecycle_ids, config=config),
            name=f"deploy-{mode}-{len(config.deckies)}",
        )

    return {
        "message": (
            f"Deploy accepted ({len(lifecycle_ids)} decky/ies, mode={mode}). "
            f"Poll /deckies/lifecycle?ids=... for completion."
        ),
        "mode": mode,
        "lifecycle_ids": list(lifecycle_ids.values()),
    }
