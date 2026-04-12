import logging
import os

from fastapi import APIRouter, Depends, HTTPException

from decnet.config import DEFAULT_MUTATE_INTERVAL, DecnetConfig, _ROOT
from decnet.engine import deploy as _deploy
from decnet.ini_loader import load_ini_from_string
from decnet.network import detect_interface, detect_subnet, get_host_ip
from decnet.web.dependencies import get_current_user, repo
from decnet.web.db.models import DeployIniRequest

router = APIRouter()


@router.post(
    "/deckies/deploy",
    tags=["Fleet Management"],
    responses={401: {"description": "Could not validate credentials"}, 400: {"description": "Validation error or INI parsing failed"}, 500: {"description": "Deployment failed"}}
)
async def api_deploy_deckies(req: DeployIniRequest, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    from decnet.fleet import build_deckies_from_ini

    try:
        ini = load_ini_from_string(req.ini_content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse INI: {e}")

    state_dict = await repo.get_state("deployment")
    ingest_log_file = os.environ.get("DECNET_INGEST_LOG_FILE")

    if state_dict:
        config = DecnetConfig(**state_dict["config"])
        subnet_cidr = ini.subnet or config.subnet
        gateway = ini.gateway or config.gateway
        host_ip = get_host_ip(config.interface)
        randomize_services = False
        # Always sync config log_file with current API ingestion target
        if ingest_log_file:
            config.log_file = ingest_log_file
    else:
        # If no state exists, we need to infer network details
        iface = ini.interface or detect_interface()
        subnet_cidr, gateway = ini.subnet, ini.gateway
        if not subnet_cidr or not gateway:
            detected_subnet, detected_gateway = detect_subnet(iface)
            subnet_cidr = subnet_cidr or detected_subnet
            gateway = gateway or detected_gateway
        host_ip = get_host_ip(iface)
        randomize_services = False
        config = DecnetConfig(
            mode="unihost",
            interface=iface,
            subnet=subnet_cidr,
            gateway=gateway,
            deckies=[],
            log_file=ingest_log_file,
            ipvlan=False,
            mutate_interval=ini.mutate_interval or DEFAULT_MUTATE_INTERVAL
        )

    try:
        new_decky_configs = build_deckies_from_ini(
            ini, subnet_cidr, gateway, host_ip, randomize_services, cli_mutate_interval=None
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Merge deckies
    existing_deckies_map = {d.name: d for d in config.deckies}
    for new_decky in new_decky_configs:
        existing_deckies_map[new_decky.name] = new_decky

    config.deckies = list(existing_deckies_map.values())

    # We call deploy(config) which regenerates docker-compose and runs `up -d --remove-orphans`.
    try:
        if os.environ.get("DECNET_CONTRACT_TEST") != "true":
            _deploy(config)

        # Persist new state to DB
        new_state_payload = {
            "config": config.model_dump(),
            "compose_path": str(_ROOT / "docker-compose.yml") if not state_dict else state_dict["compose_path"]
        }
        await repo.set_state("deployment", new_state_payload)
    except Exception as e:
        logging.getLogger("decnet.web.api").exception("Deployment failed: %s", e)
        raise HTTPException(status_code=500, detail="Deployment failed. Check server logs for details.")

    return {"message": "Deckies deployed successfully"}
