import os

from fastapi import APIRouter, Depends, HTTPException

from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.config import DEFAULT_MUTATE_INTERVAL, DecnetConfig, _ROOT
from decnet.engine import deploy as _deploy
from decnet.ini_loader import load_ini_from_string
from decnet.network import detect_interface, detect_subnet, get_host_ip
from decnet.web.dependencies import require_admin, repo
from decnet.web.db.models import DeployIniRequest
from decnet.web.router.swarm.api_deploy_swarm import dispatch_decnet_config

log = get_logger("api")

router = APIRouter()


@router.post(
    "/deckies/deploy",
    tags=["Fleet Management"],
    responses={
        400: {"description": "Bad Request (e.g. malformed JSON)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        409: {"description": "Configuration conflict (e.g. invalid IP allocation or network mismatch)"},
        422: {"description": "Invalid INI config or schema validation error"},
        500: {"description": "Deployment failed"}
    }
)
@_traced("api.deploy_deckies")
async def api_deploy_deckies(req: DeployIniRequest, admin: dict = Depends(require_admin)) -> dict[str, str]:
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
            subnet_cidr, gateway = ini.subnet, ini.gateway
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

    try:
        new_decky_configs = build_deckies_from_ini(
            ini, subnet_cidr, gateway, host_ip, False, cli_mutate_interval=None
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

    # Merge deckies
    existing_deckies_map = {d.name: d for d in config.deckies}
    for new_decky in new_decky_configs:
        existing_deckies_map[new_decky.name] = new_decky

    # Enforce deployment limit
    limits_state = await repo.get_state("config_limits")
    deployment_limit = limits_state.get("deployment_limit", 10) if limits_state else 10
    if len(existing_deckies_map) > deployment_limit:
        raise HTTPException(
            status_code=409,
            detail=f"Deployment would result in {len(existing_deckies_map)} deckies, "
                   f"exceeding the configured limit of {deployment_limit}",
        )

    config.deckies = list(existing_deckies_map.values())

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

        try:
            result = await dispatch_decnet_config(config, repo, dry_run=False, no_cache=False)
        except HTTPException:
            raise
        except Exception as e:
            log.exception("swarm-auto deploy dispatch failed: %s", e)
            raise HTTPException(status_code=500, detail="Swarm dispatch failed. Check server logs.")

        await repo.set_state("deployment", {
            "config": config.model_dump(),
            "compose_path": state_dict["compose_path"] if state_dict else "",
        })

        failed = [r for r in result.results if not r.ok]
        if failed:
            detail = "; ".join(f"{r.host_name}: {r.detail}" for r in failed)
            raise HTTPException(status_code=502, detail=f"Partial swarm deploy failure — {detail}")
        return {
            "message": f"Deckies deployed across {len(result.results)} swarm host(s)",
            "mode": "swarm",
        }

    # Unihost path — docker-compose on the master itself.
    try:
        if os.environ.get("DECNET_CONTRACT_TEST") != "true":
            _deploy(config)

        new_state_payload = {
            "config": config.model_dump(),
            "compose_path": str(_ROOT / "docker-compose.yml") if not state_dict else state_dict["compose_path"]
        }
        await repo.set_state("deployment", new_state_payload)
    except Exception as e:
        log.exception("Deployment failed: %s", e)
        raise HTTPException(status_code=500, detail="Deployment failed. Check server logs for details.")

    return {"message": "Deckies deployed successfully", "mode": "unihost"}
