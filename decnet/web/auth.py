# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
import jwt
import bcrypt

from decnet.env import DECNET_JWT_SECRET, DECNET_JWT_EXP_MINUTES

SECRET_KEY: str = DECNET_JWT_SECRET
ALGORITHM: str = "HS256"
# Live constant — sourced from env DECNET_JWT_EXP_MINUTES (default 240 / 4 h).
# Idle/inactivity timeout is intentionally not implemented: jti denylist covers
# explicit logout and the 4 h absolute TTL bounds the worst-case exposure window.
# Accept-risk: LOW / pre-v1 — revisit at v1 when user-facing session UX lands.
ACCESS_TOKEN_EXPIRE_MINUTES: int = DECNET_JWT_EXP_MINUTES

# Pinned issuer/audience/type so a token signed with DECNET_JWT_SECRET for any
# OTHER purpose (or by a future co-tenant of the secret) is not accepted by the
# dashboard verifier. Issuance stamps these; _decode_payload requires + verifies
# them. Keep these two modules in lockstep — they are a single trust contract.
JWT_ISSUER: str = "decnet"
JWT_AUDIENCE: str = "decnet-dashboard"
JWT_TYPE: str = "access"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # [:72] is a defensive safety-net against bcrypt silent truncation.
    # Validated callers already reject >72-byte passwords via field_validator,
    # so this slice is unreachable for well-formed input.
    return bcrypt.checkpw(
        plain_password.encode("utf-8")[:72],
        hashed_password.encode("utf-8")
    )


def get_password_hash(password: str) -> str:
    # Use a cost factor of 12 (default for passlib/bcrypt).
    # [:72] is a defensive safety-net; field_validator rejects >72-byte input
    # before it reaches this function.
    _salt: bytes = bcrypt.gensalt(rounds=12)
    _hashed: bytes = bcrypt.hashpw(password.encode("utf-8")[:72], _salt)
    return _hashed.decode("utf-8")


async def averify_password(plain_password: str, hashed_password: str) -> bool:
    # bcrypt is CPU-bound and ~250ms/call; keep it off the event loop.
    return await asyncio.to_thread(verify_password, plain_password, hashed_password)


async def ahash_password(password: str) -> str:
    return await asyncio.to_thread(get_password_hash, password)


def create_access_token(data: dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    _to_encode: dict[str, Any] = data.copy()
    _expire: datetime
    if expires_delta:
        _expire = datetime.now(timezone.utc) + expires_delta
    else:
        _expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    _to_encode.update({"exp": _expire})
    _to_encode.update({"iat": datetime.now(timezone.utc)})
    # Pin issuer / audience / token-type so the verifier can reject tokens
    # minted for any other purpose with the same shared secret.
    _to_encode.setdefault("iss", JWT_ISSUER)
    _to_encode.setdefault("aud", JWT_AUDIENCE)
    _to_encode.setdefault("typ", JWT_TYPE)
    _encoded_jwt: str = jwt.encode(_to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return _encoded_jwt
