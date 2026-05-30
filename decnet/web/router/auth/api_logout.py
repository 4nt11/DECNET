# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import get_token_claims, invalidate_token_cache, repo
from decnet.web.db.models import MessageResponse

router = APIRouter()


@router.post(
    "/auth/logout",
    tags=["Authentication"],
    response_model=MessageResponse,
    responses={
        401: {"description": "Missing, invalid, or already-revoked token"},
    },
)
@_traced("api.logout")
async def logout(claims: dict[str, Any] = Depends(get_token_claims)) -> dict[str, str]:
    """Revoke the presented token by adding its ``jti`` to the denylist.

    Single-session logout: only *this* token dies. "Log out everywhere" is a
    separate lever (``tokens_valid_from``) driven by password/role changes.
    Reachable for must_change_password users so they can always end a session.
    """
    # exp is always present (create_access_token stamps it); jti is guaranteed
    # by get_token_claims, which rejects tokens without one.
    expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
    await repo.revoke_token(claims["jti"], claims["uuid"], expires_at)
    # Drop the local negative-cache entry so reuse 401s immediately, not after TTL.
    invalidate_token_cache(claims["jti"])
    return {"message": "Logged out"}
