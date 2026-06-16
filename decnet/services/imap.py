# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "imap"

# Repo-root default seed dir.  When service_cfg["email_seed"] is unset,
# fall back to ``$PROJROOT/bait/`` if that directory exists on the host.
# Operator drops .eml / .json files there to ship a deployment-wide bait
# corpus without per-decky config.  Missing dir → no env var, no volume,
# template uses its hardcoded baseline alone.
_PROJ_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_SEED_DIR = _PROJ_ROOT / "bait"

_SEED_CONTAINER_PATH = "/var/spool/decnet-emails/seed"


def _resolve_seed_path(service_cfg: dict | None) -> str | None:
    """Return the host path to bind-mount, or None.

    Precedence:
    1. service_cfg["email_seed"] if set + truthy.
    2. ``$PROJROOT/bait/`` if it exists.
    3. None.
    """
    if service_cfg:
        seed = service_cfg.get("email_seed")
        if seed:
            return str(Path(str(seed)).expanduser().resolve())
    if _DEFAULT_SEED_DIR.is_dir():
        return str(_DEFAULT_SEED_DIR.resolve())
    return None


class IMAPService(BaseService):
    name = "imap"
    ports = [143, 993]
    default_image = "build"
    # Optional config:
    #   email_seed: host path to a directory of .eml/.json files OR a
    #               single .json/.eml.  Mounted read-only into the
    #               container; entries concatenate with the hardcoded
    #               bait list (additive to realism-engine output).
    # Default fallback: $PROJROOT/bait/ when present.

    def compose_fragment(self, decky_name: str, log_target: str | None = None, service_cfg: dict | None = None) -> dict:
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-imap",
            "restart": "unless-stopped",
            "environment": {"NODE_NAME": decky_name},
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        host_path = _resolve_seed_path(service_cfg)
        if host_path:
            fragment["environment"]["IMAP_EMAIL_SEED"] = _SEED_CONTAINER_PATH
            fragment.setdefault("volumes", []).append(
                f"{host_path}:{_SEED_CONTAINER_PATH}:ro"
            )
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
