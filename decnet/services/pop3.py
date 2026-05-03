from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "pop3"


_SEED_CONTAINER_PATH = "/var/spool/decnet-emails/seed"


class POP3Service(BaseService):
    name = "pop3"
    ports = [110, 995]
    default_image = "build"
    # Optional config:
    #   email_seed: host path to a directory of .eml/.json files OR a
    #               single .json/.eml.  Mounted read-only; entries
    #               concatenate with the hardcoded bait list.

    def compose_fragment(self, decky_name: str, log_target: str | None = None, service_cfg: dict | None = None) -> dict:
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-pop3",
            "restart": "unless-stopped",
            "environment": {"NODE_NAME": decky_name},
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        if service_cfg:
            seed = service_cfg.get("email_seed")
            if seed:
                host_path = str(Path(str(seed)).expanduser().resolve())
                fragment["environment"]["POP3_EMAIL_SEED"] = _SEED_CONTAINER_PATH
                fragment.setdefault("volumes", []).append(
                    f"{host_path}:{_SEED_CONTAINER_PATH}:ro"
                )
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
