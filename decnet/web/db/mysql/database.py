# SPDX-License-Identifier: AGPL-3.0-or-later
"""
MySQL async engine factory.

Builds a SQLAlchemy AsyncEngine against MySQL using the ``asyncmy`` driver.

Connection info is resolved (in order of precedence):

1. An explicit ``url`` argument passed to :func:`get_async_engine`
2. ``DECNET_DB_URL``                 — full SQLAlchemy URL
3. Component env vars:
   ``DECNET_DB_HOST`` (default ``localhost``)
   ``DECNET_DB_PORT`` (default ``3306``)
   ``DECNET_DB_NAME`` (default ``decnet``)
   ``DECNET_DB_USER`` (default ``decnet``)
   ``DECNET_DB_PASSWORD`` (default empty — raises unless pytest is running)
"""
from __future__ import annotations

import os
from typing import Optional
from urllib.parse import quote_plus

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


DEFAULT_POOL_SIZE = int(os.environ.get("DECNET_DB_POOL_SIZE", "20"))
DEFAULT_MAX_OVERFLOW = int(os.environ.get("DECNET_DB_MAX_OVERFLOW", "40"))
DEFAULT_POOL_RECYCLE = int(os.environ.get("DECNET_DB_POOL_RECYCLE", "3600"))
DEFAULT_POOL_PRE_PING = os.environ.get("DECNET_DB_POOL_PRE_PING", "true").lower() == "true"


def build_mysql_url(
    host: Optional[str] = None,
    port: Optional[int] = None,
    database: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> str:
    """Compose an async SQLAlchemy URL for MySQL using the asyncmy driver.

    Component args override env vars. Password is percent-encoded so special
    characters (``@``, ``:``, ``/``…) don't break URL parsing.
    """
    host = host or os.environ.get("DECNET_DB_HOST") or "localhost"
    port = port or int(os.environ.get("DECNET_DB_PORT") or "3306")
    database = database or os.environ.get("DECNET_DB_NAME") or "decnet"
    user = user or os.environ.get("DECNET_DB_USER") or "decnet"

    if password is None:
        password = os.environ.get("DECNET_DB_PASSWORD") or ""

    # Allow empty passwords during tests, gated on the explicit, non-attacker-
    # injectable DECNET_TESTING=1 flag (set by the test harness) rather than
    # the attacker-controllable PYTEST* namespace (V2.1.7). Outside tests, an
    # empty MySQL password is almost never intentional.
    if not password and os.environ.get("DECNET_TESTING") != "1":
        raise ValueError(
            "DECNET_DB_PASSWORD is not set. Either export it, set DECNET_DB_URL, "
            "or run under the test harness (DECNET_TESTING=1) for an empty-password default."
        )

    pw_enc = quote_plus(password)
    user_enc = quote_plus(user)
    return f"mysql+asyncmy://{user_enc}:{pw_enc}@{host}:{port}/{database}"


def resolve_url(url: Optional[str] = None) -> str:
    """Pick a connection URL: explicit arg → DECNET_DB_URL env → built from components."""
    if url:
        return url
    env_url = os.environ.get("DECNET_DB_URL")
    if env_url:
        return env_url
    return build_mysql_url()


def get_async_engine(
    url: Optional[str] = None,
    *,
    pool_size: int = DEFAULT_POOL_SIZE,
    max_overflow: int = DEFAULT_MAX_OVERFLOW,
    pool_recycle: int = DEFAULT_POOL_RECYCLE,
    pool_pre_ping: bool = DEFAULT_POOL_PRE_PING,
    echo: bool = False,
) -> AsyncEngine:
    """Create an AsyncEngine for MySQL.

    Defaults tuned for a dashboard workload: a modest pool, hourly recycle
    to sidestep MySQL's idle-connection reaper, and pre-ping to fail fast
    if a pooled connection has been killed server-side.
    """
    dsn = resolve_url(url)
    return create_async_engine(
        dsn,
        echo=echo,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_recycle=pool_recycle,
        pool_pre_ping=pool_pre_ping,
    )
