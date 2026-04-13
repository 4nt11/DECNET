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


async def _decode_token(request: Request) -> str:
    """Decode and validate a Bearer JWT, returning the user UUID."""
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


async def get_current_user(request: Request) -> str:
    """Auth dependency — enforces must_change_password."""
    _user_uuid = await _decode_token(request)
    _user = await repo.get_user_by_uuid(_user_uuid)
    if _user and _user.get("must_change_password"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before accessing this resource",
        )
    return _user_uuid


async def get_current_user_unchecked(request: Request) -> str:
    """Auth dependency — skips must_change_password enforcement.
    Use only for endpoints that must remain reachable with the flag set (e.g. change-password).
    """
    return await _decode_token(request)
