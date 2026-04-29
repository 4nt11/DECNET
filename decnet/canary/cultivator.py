"""Realism contract adapter for canary generators.

Stage 7 of the realism migration.  The orchestrator's planner picks a
``canary_*`` :class:`~decnet.realism.taxonomy.ContentClass` 1–3% of
the time on file ticks; this module turns that pick into a
:class:`~decnet.canary.base.CanaryArtifact` (bytes the SSH driver
plants) plus a persisted :class:`~decnet.web.db.models.CanaryToken`
row so the canary worker recognises the slug when an attacker trips
it.

What this is NOT: it doesn't pick *when* canaries fire — that's the
realism planner's job.  It doesn't decide *where* on the filesystem
the canary lands beyond what realism naming + persona conventions
already produce.  It's a thin bytes-and-row factory bolted onto the
realism contract.

Stealth (per ``feedback_stealth.md``): we never leak the
``DECNET`` literal into anything that survives to the planted file.
The underlying generators are already stealth-clean; this wrapper
must not undo that.
"""
from __future__ import annotations

import os
import secrets as _secrets
from datetime import datetime, timezone
from typing import Any, Optional

from decnet.canary.base import CanaryArtifact, CanaryContext
from decnet.canary.factory import get_generator
from decnet.logging import get_logger
from decnet.realism.personas import login_for
from decnet.realism.taxonomy import ContentClass, Plan

log = get_logger("canary.cultivator")


# realism content_class → canary generator name.  Mirrors
# :data:`decnet.canary.factory.KNOWN_GENERATORS`.
_CLASS_TO_GENERATOR: dict[ContentClass, str] = {
    ContentClass.CANARY_AWS_CREDS: "aws_creds",
    ContentClass.CANARY_ENV_FILE: "env_file",
    ContentClass.CANARY_GIT_CONFIG: "git_config",
    ContentClass.CANARY_SSH_KEY: "ssh_key",
    ContentClass.CANARY_HONEYDOC: "honeydoc",
    ContentClass.CANARY_HONEYDOC_DOCX: "honeydoc_docx",
    ContentClass.CANARY_HONEYDOC_PDF: "honeydoc_pdf",
    ContentClass.CANARY_MYSQL_DUMP: "mysql_dump",
    ContentClass.CANARY_FINGERPRINT_HTML: "fingerprint_html",
    ContentClass.CANARY_FINGERPRINT_SVG: "fingerprint_svg",
}


# Generator → CanaryKind. The trip surface (HTTP slug callback / DNS
# resolution / passive bait) determines how the canary worker matches
# an attacker callback to this token. Aligned with
# :data:`decnet.web.db.models.canary.CanaryKind`.
_GENERATOR_TO_KIND: dict[str, str] = {
    "aws_creds": "aws_passive",   # no embedded callback; passive bait
    "env_file": "http",
    "git_config": "http",
    "honeydoc": "http",
    "honeydoc_docx": "http",
    "honeydoc_pdf": "http",
    "ssh_key": "dns",             # trip is DNS resolution of host comment
    "mysql_dump": "dns",          # trip is DNS resolution of subdomain
    "fingerprint_html": "http",   # obfuscated JS beacons GET /c/<slug>
    "fingerprint_svg": "http",    # same, embedded inside SVG <script>
}


# Path conventions per generator.  The realism planner doesn't know
# about decoy-realistic credential locations (``~/.aws/credentials``,
# ``~/.git/config``); we map them per-class here so the planted
# artifact lands somewhere an attacker would actually look.
_DEFAULT_PATH: dict[ContentClass, str] = {
    ContentClass.CANARY_AWS_CREDS: "/home/{persona}/.aws/credentials",
    ContentClass.CANARY_ENV_FILE: "/home/{persona}/app/.env",
    ContentClass.CANARY_GIT_CONFIG: "/home/{persona}/.git/config",
    ContentClass.CANARY_SSH_KEY: "/home/{persona}/.ssh/id_rsa",
    ContentClass.CANARY_HONEYDOC: "/home/{persona}/Documents/notes.html",
    ContentClass.CANARY_HONEYDOC_DOCX: "/home/{persona}/Documents/Q3-Operations-Review.docx",
    ContentClass.CANARY_HONEYDOC_PDF: "/home/{persona}/Documents/Q3-Operations-Review.pdf",
    ContentClass.CANARY_MYSQL_DUMP: "/var/backups/db_backup.sql",
    ContentClass.CANARY_FINGERPRINT_HTML: "/home/{persona}/Documents/asset_directory.html",
    ContentClass.CANARY_FINGERPRINT_SVG: "/home/{persona}/Documents/network_topology.svg",
}


def _path_for(plan: Plan) -> str:
    """Produce the canary placement path for *plan*.

    The realism planner already filled in ``plan.target_path`` from
    the namer, but canary placements have stronger conventions
    (``~/.aws/credentials``, ``~/.ssh/id_rsa``) than the realism
    namer's vocabulary.  When :data:`_DEFAULT_PATH` has an entry,
    that wins.
    """
    template = _DEFAULT_PATH.get(plan.content_class)
    if template is None:
        return plan.target_path
    return template.format(persona=login_for(plan.persona))


def _new_callback_token() -> str:
    """16 url-safe bytes — same shape canary slug fields use elsewhere."""
    return _secrets.token_urlsafe(16)


async def cultivate(
    plan: Plan,
    repo: Any,
    *,
    http_base: Optional[str] = None,
    dns_zone: Optional[str] = None,
    created_by: str = "system",
) -> CanaryArtifact:
    """Realism-driven canary plant.

    Build a :class:`CanaryContext`, ask the right generator for bytes,
    persist a ``canary_tokens`` row so the canary worker can attribute
    callbacks to this token, and return the artifact for the SSH
    driver to plant.

    *http_base* and *dns_zone* default to ``DECNET_CANARY_HTTP_BASE``
    and ``DECNET_CANARY_DNS_ZONE`` env vars respectively — same
    pattern the canary worker uses.  When both are empty, generators
    that need a callback host (``ssh_key`` DNS, ``mysql_dump``)
    raise; the planner's caller logs and falls back to a non-canary
    plan.
    """
    if not plan.content_class.is_canary():
        raise ValueError(
            f"cultivate() called with non-canary content_class="
            f"{plan.content_class!r}"
        )
    gen_name = _CLASS_TO_GENERATOR.get(plan.content_class)
    if gen_name is None:
        raise KeyError(
            f"no canary generator mapped for content_class="
            f"{plan.content_class!r}"
        )

    callback_token = _new_callback_token()
    ctx = CanaryContext(
        callback_token=callback_token,
        http_base=http_base or os.environ.get("DECNET_CANARY_HTTP_BASE", ""),
        dns_zone=dns_zone or os.environ.get("DECNET_CANARY_DNS_ZONE", ""),
        persona="linux",  # all our deckies are POSIX in MVP
    )
    generator = get_generator(gen_name)
    artifact = generator.generate(ctx)

    # The generator returns ``path=""`` (planter fills it normally).
    # We have a realism-derived path on hand; stuff it in for the SSH
    # driver's plant_file call AND the canary_tokens row.
    placement_path = _path_for(plan)

    # Persist the token row before planting so the canary worker can
    # attribute a callback if the artifact trips during the plant
    # itself (improbable but possible — DOCX viewers can preview
    # autoplay-style).
    token_data: dict = {
        "kind": _GENERATOR_TO_KIND.get(gen_name, "http"),
        "decky_name": plan.decky_name,
        "instrumenter": None,
        "generator": gen_name,
        "placement_path": placement_path,
        "callback_token": callback_token,
        "secret_seed": callback_token,  # deterministic re-seed compatible
        "placed_at": datetime.now(timezone.utc),
        "created_by": created_by,
        "state": "planted",
    }
    if artifact.fingerprint_nonce is not None:
        token_data["fingerprint_nonce"] = artifact.fingerprint_nonce
    await repo.create_canary_token(token_data)

    # Carry the placement_path on the artifact so the orchestrator's
    # plant_file call uses it.  We don't mutate the generator's
    # original — copy with the new path.
    return CanaryArtifact(
        path=placement_path,
        content=artifact.content,
        mode=artifact.mode,
        mtime_offset=artifact.mtime_offset,
        instrumenter=artifact.instrumenter,
        generator=artifact.generator,
        notes=list(artifact.notes),
    )
