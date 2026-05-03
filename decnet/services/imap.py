from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "imap"


_SEED_CONTAINER_PATH = "/var/spool/decnet-emails/seed"


class IMAPService(BaseService):
    name = "imap"
    ports = [143, 993]
    default_image = "build"
    # Optional config:
    #   email_seed: host path to a directory of .eml/.json files OR a
    #               single .json/.eml.  Mounted read-only into the
    #               container; entries concatenate with the hardcoded
    #               bait list (additive to realism-engine output).

    def compose_fragment(self, decky_name: str, log_target: str | None = None, service_cfg: dict | None = None) -> dict:
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-imap",
            "restart": "unless-stopped",
            "environment": {"NODE_NAME": decky_name},
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        if service_cfg:
            seed = service_cfg.get("email_seed")
            if seed:
                host_path = str(Path(str(seed)).expanduser().resolve())
                fragment["environment"]["IMAP_EMAIL_SEED"] = _SEED_CONTAINER_PATH
                fragment.setdefault("volumes", []).append(
                    f"{host_path}:{_SEED_CONTAINER_PATH}:ro"
                )
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
