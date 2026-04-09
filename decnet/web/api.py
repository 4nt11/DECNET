import uuid
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any, AsyncGenerator, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, status, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field

from decnet.web.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    get_password_hash,
    verify_password,
)
from decnet.web.sqlite_repository import SQLiteRepository
from decnet.web.ingester import log_ingestion_worker
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
import asyncio

repo: SQLiteRepository = SQLiteRepository()
ingestion_task: Optional[asyncio.Task[Any]] = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global ingestion_task
    await repo.initialize()
    # Create default admin if no users exist
    _admin_user: Optional[dict[str, Any]] = await repo.get_user_by_username(DECNET_ADMIN_USER)
    if not _admin_user:
        await repo.create_user(
            {
                "uuid": str(uuid.uuid4()),
                "username": DECNET_ADMIN_USER,
                "password_hash": get_password_hash(DECNET_ADMIN_PASSWORD),
                "role": "admin",
                "must_change_password": True
            }
        )
    
    # Start background ingestion task
    ingestion_task = asyncio.create_task(log_ingestion_worker(repo))
    
    yield
    
    # Shutdown ingestion task
    if ingestion_task:
        ingestion_task.cancel()


app: FastAPI = FastAPI(
    title="DECNET Web Dashboard API", 
    version="1.0.0", 
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


oauth2_scheme: OAuth2PasswordBearer = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(request: Request) -> str:
    _credentials_exception: HTTPException = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Extract token from header or query param
    token: str | None = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    elif request.query_params.get("token"):
        token = request.query_params.get("token")
        
    if not token:
        raise _credentials_exception

    try:
        _payload: dict[str, Any] = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        _user_uuid: Optional[str] = _payload.get("uuid")
        if _user_uuid is None:
            raise _credentials_exception
        return _user_uuid
    except jwt.PyJWTError:
        raise _credentials_exception


class Token(BaseModel):
    access_token: str
    token_type: str
    must_change_password: bool = False


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class LogsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: list[dict[str, Any]]


@app.post("/api/v1/auth/login", response_model=Token)
async def login(request: LoginRequest) -> dict[str, Any]:
    _user: Optional[dict[str, Any]] = await repo.get_user_by_username(request.username)
    if not _user or not verify_password(request.password, _user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _access_token_expires: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Token uses uuid instead of sub
    _access_token: str = create_access_token(
        data={"uuid": _user["uuid"]}, expires_delta=_access_token_expires
    )
    return {
        "access_token": _access_token, 
        "token_type": "bearer",
        "must_change_password": bool(_user.get("must_change_password", False))
    }


@app.post("/api/v1/auth/change-password")
async def change_password(request: ChangePasswordRequest, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    _user: Optional[dict[str, Any]] = await repo.get_user_by_uuid(current_user)
    if not _user or not verify_password(request.old_password, _user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect old password",
        )
    
    _new_hash: str = get_password_hash(request.new_password)
    await repo.update_user_password(current_user, _new_hash, must_change_password=False)
    return {"message": "Password updated successfully"}


@app.get("/api/v1/logs", response_model=LogsResponse)
async def get_logs(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = None,
    current_user: str = Depends(get_current_user)
) -> dict[str, Any]:
    _logs: list[dict[str, Any]] = await repo.get_logs(limit=limit, offset=offset, search=search)
    _total: int = await repo.get_total_logs(search=search)
    return {
        "total": _total,
        "limit": limit,
        "offset": offset,
        "data": _logs
    }


class StatsResponse(BaseModel):
    total_logs: int
    unique_attackers: int
    active_deckies: int
    deployed_deckies: int


@app.get("/api/v1/stats", response_model=StatsResponse)
async def get_stats(current_user: str = Depends(get_current_user)) -> dict[str, Any]:
    return await repo.get_stats_summary()


@app.get("/api/v1/deckies")
async def get_deckies(current_user: str = Depends(get_current_user)) -> list[dict[str, Any]]:
    return await repo.get_deckies()


class MutateIntervalRequest(BaseModel):
    mutate_interval: int | None


@app.post("/api/v1/deckies/{decky_name}/mutate")
async def api_mutate_decky(decky_name: str, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    from decnet.mutator import mutate_decky
    success = mutate_decky(decky_name)
    if success:
        return {"message": f"Successfully mutated {decky_name}"}
    raise HTTPException(status_code=404, detail=f"Decky {decky_name} not found or failed to mutate")


@app.put("/api/v1/deckies/{decky_name}/mutate-interval")
async def api_update_mutate_interval(decky_name: str, req: MutateIntervalRequest, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    from decnet.config import load_state, save_state
    state = load_state()
    if not state:
        raise HTTPException(status_code=500, detail="No active deployment")
    config, compose_path = state
    decky = next((d for d in config.deckies if d.name == decky_name), None)
    if not decky:
        raise HTTPException(status_code=404, detail="Decky not found")
    decky.mutate_interval = req.mutate_interval
    save_state(config, compose_path)
    return {"message": "Mutation interval updated"}


@app.get("/api/v1/stream")
async def stream_events(
    request: Request, 
    last_event_id: int = Query(0, alias="lastEventId"), 
    search: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    current_user: str = Depends(get_current_user)
) -> StreamingResponse:
    import json
    import asyncio
    
    async def event_generator() -> AsyncGenerator[str, None]:
        # Start tracking from the provided ID, or current max if 0
        last_id = last_event_id
        if last_id == 0:
            last_id = await repo.get_max_log_id()
            
        stats_interval_sec = 10
        loops_since_stats = 0
        
        while True:
            if await request.is_disconnected():
                break

            # Poll for new logs
            new_logs = await repo.get_logs_after_id(last_id, limit=50, search=search, start_time=start_time, end_time=end_time)
            if new_logs:
                # Update last_id to the max id in the fetched batch
                last_id = max(log["id"] for log in new_logs)
                payload = json.dumps({"type": "logs", "data": new_logs})
                yield f"event: message\ndata: {payload}\n\n"
                
                # If we have new logs, stats probably changed, so force a stats update
                loops_since_stats = stats_interval_sec
            
            # Periodically poll for stats
            if loops_since_stats >= stats_interval_sec:
                stats = await repo.get_stats_summary()
                payload = json.dumps({"type": "stats", "data": stats})
                yield f"event: message\ndata: {payload}\n\n"

                # Also yield histogram
                histogram = await repo.get_log_histogram(search=search, start_time=start_time, end_time=end_time, interval_minutes=15)
                hist_payload = json.dumps({"type": "histogram", "data": histogram})
                yield f"event: message\ndata: {hist_payload}\n\n"

                loops_since_stats = 0
                
            loops_since_stats += 1
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


class DeployIniRequest(BaseModel):
    ini_content: str = Field(..., min_length=5, max_length=512 * 1024)

@app.post("/api/v1/deckies/deploy")
async def api_deploy_deckies(req: DeployIniRequest, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    from decnet.ini_loader import load_ini_from_string
    from decnet.cli import _build_deckies_from_ini
    from decnet.config import load_state, DecnetConfig, DEFAULT_MUTATE_INTERVAL
    from decnet.network import detect_interface, detect_subnet, get_host_ip
    from decnet.deployer import deploy as _deploy
    import logging
    import os

    try:
        ini = load_ini_from_string(req.ini_content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse INI: {e}")

    state = load_state()
    ingest_log_file = os.environ.get("DECNET_INGEST_LOG_FILE")
    
    if state:
        config, _ = state
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
            log_target=ini.log_target,
            log_file=ingest_log_file,
            ipvlan=False,
            mutate_interval=ini.mutate_interval or DEFAULT_MUTATE_INTERVAL
        )

    try:
        new_decky_configs = _build_deckies_from_ini(
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
        _deploy(config)
    except Exception as e:
        logging.getLogger("decnet.web.api").error(f"Deployment failed: {e}")
        raise HTTPException(status_code=500, detail=f"Deployment failed: {e}")

    return {"message": "Deckies deployed successfully"}
