from typing import Any, Optional
from pathlib import Path

import jwt
from fastapi import HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer

from decnet.web.auth import ALGORITHM, SECRET_KEY
from decnet.web.db.sqlite.repository import SQLiteRepository

# Root directory for database
_ROOT_DIR = Path(__file__).parent.parent.parent.absolute()
DB_PATH = _ROOT_DIR / "decnet.db"

# Shared repository instance
repo = SQLiteRepository(db_path=str(DB_PATH))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(request: Request) -> str:
    _credentials_exception = HTTPException(
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
