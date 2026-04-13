from datetime import datetime, timedelta, timezone
from typing import Optional, Any
import jwt
import bcrypt

from decnet.env import DECNET_JWT_SECRET

SECRET_KEY: str = DECNET_JWT_SECRET
ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8")[:72],
        hashed_password.encode("utf-8")
    )


def get_password_hash(password: str) -> str:
    # Use a cost factor of 12 (default for passlib/bcrypt)
    _salt: bytes = bcrypt.gensalt(rounds=12)
    _hashed: bytes = bcrypt.hashpw(password.encode("utf-8")[:72], _salt)
    return _hashed.decode("utf-8")


def create_access_token(data: dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    _to_encode: dict[str, Any] = data.copy()
    _expire: datetime
    if expires_delta:
        _expire = datetime.now(timezone.utc) + expires_delta
    else:
        _expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    _to_encode.update({"exp": _expire})
    _to_encode.update({"iat": datetime.now(timezone.utc)})
    _encoded_jwt: str = jwt.encode(_to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return _encoded_jwt
