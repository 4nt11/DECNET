import uuid
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any, AsyncGenerator

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from decnet.web.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    get_password_hash,
    verify_password,
)
from decnet.web.sqlite_repository import SQLiteRepository

repo: SQLiteRepository = SQLiteRepository()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    await repo.initialize()
    # Create default admin if no users exist
    admin_user: dict[str, Any] | None = await repo.get_user_by_username("admin")
    if not admin_user:
        await repo.create_user(
            {
                "uuid": str(uuid.uuid4()),
                "username": "admin",
                "password_hash": get_password_hash("admin"),
                "role": "admin",
            }
        )
    yield


app: FastAPI = FastAPI(
    title="DECNET Web Dashboard API", 
    version="1.0.0", 
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


oauth2_scheme: OAuth2PasswordBearer = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload: dict[str, Any] = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_uuid: str | None = payload.get("uuid")
        if user_uuid is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    return user_uuid


class Token(BaseModel):
    access_token: str
    token_type: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LogsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: list[dict[str, Any]]


@app.post("/api/v1/auth/login", response_model=Token)
async def login(request: LoginRequest) -> dict[str, str]:
    user: dict[str, Any] | None = await repo.get_user_by_username(request.username)
    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Token uses uuid instead of sub
    access_token: str = create_access_token(
        data={"uuid": user["uuid"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/v1/logs", response_model=LogsResponse)
async def get_logs(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: str | None = None,
    current_user: str = Depends(get_current_user)
) -> dict[str, Any]:
    logs: list[dict[str, Any]] = await repo.get_logs(limit=limit, offset=offset, search=search)
    total: int = await repo.get_total_logs(search=search)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "data": logs
    }
