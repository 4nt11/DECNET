import uuid
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from decnet.web.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
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


class Token(BaseModel):
    access_token: str
    token_type: str


class LoginRequest(BaseModel):
    username: str
    password: str


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
