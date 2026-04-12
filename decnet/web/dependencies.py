from typing import Any, Optional

import jwt
from fastapi import HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer

from decnet.web.auth import ALGORITHM, SECRET_KEY
from decnet.web.db.repository import BaseRepository
from decnet.web.db.factory import get_repository

# Shared repository singleton
_repo: Optional[BaseRepository] = None

def get_repo() -> BaseRepository:
    """FastAPI dependency to inject the configured repository."""
    global _repo
    if _repo is None:
        _repo = get_repository()
    return _repo

repo = get_repo()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_stream_user(request: Request, token: Optional[str] = None) -> str:
    """Auth dependency for SSE endpoints — accepts Bearer header OR ?token= query param.
    EventSource does not support custom headers, so the query-string fallback is intentional here only.
    """
    _credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    auth_header = request.headers.get("Authorization")
    resolved: str | None = (
        auth_header.split(" ", 1)[1]
        if auth_header and auth_header.startswith("Bearer ")
        else token
    )
    if not resolved:
        raise _credentials_exception

    try:
        _payload: dict[str, Any] = jwt.decode(resolved, SECRET_KEY, algorithms=[ALGORITHM])
        _user_uuid: Optional[str] = _payload.get("uuid")
        if _user_uuid is None:
            raise _credentials_exception
        return _user_uuid
    except jwt.PyJWTError:
        raise _credentials_exception


async def get_current_user(request: Request) -> str:
    _credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    auth_header = request.headers.get("Authorization")
    token: str | None = (
        auth_header.split(" ", 1)[1]
        if auth_header and auth_header.startswith("Bearer ")
        else None
    )
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
