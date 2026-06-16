# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fake ``.env`` with embedded callback URLs.

Modern web stacks read environment variables for everything from
database DSNs to webhook URLs, so dropping a few realistic-looking
``KEY=value`` pairs alongside the canary URL is unremarkable.  The
slug appears in two fields:

* ``API_BASE_URL`` — the obvious one; an attacker scripting against
  the credentials hits the worker on first invocation.
* ``WEBHOOK_NOTIFY_URL`` — secondary, in case the attacker greps for
  ``WEBHOOK`` and pivots there.

Other fields (``DB_PASSWORD``, ``REDIS_URL``, ``JWT_SECRET``) are
plausible but inert — they're realism filler, not detection
mechanisms.
"""
from __future__ import annotations

import hashlib

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryGenerator


def _stable_token(seed: str, prefix: str = "") -> str:
    h = hashlib.sha256((prefix + seed).encode()).hexdigest()
    return h[:32]


class EnvFileGenerator(CanaryGenerator):
    name = "env_file"

    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        base = ctx.http_base.rstrip("/")
        slug = ctx.callback_token
        api_url = f"{base}/c/{slug}"
        body = (
            "# Production environment — DO NOT COMMIT\n"
            f"API_BASE_URL={api_url}\n"
            f"WEBHOOK_NOTIFY_URL={api_url}/webhook\n"
            f"DB_PASSWORD={_stable_token(slug, 'db:')}\n"
            f"REDIS_URL=redis://:{_stable_token(slug, 'redis:')[:16]}@redis.internal:6379/0\n"
            f"JWT_SECRET={_stable_token(slug, 'jwt:')}\n"
            "LOG_LEVEL=info\n"
            "ENVIRONMENT=production\n"
        )
        return CanaryArtifact(
            path="",
            content=body.encode("utf-8"),
            mode=0o600,
            mtime_offset=-86400 * 7,  # last edited a week ago
            generator=self.name,
            notes=[
                f"API_BASE_URL embeds {api_url}",
                f"WEBHOOK_NOTIFY_URL embeds {api_url}/webhook",
            ],
        )
