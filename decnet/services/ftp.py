from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "ftp"


class FTPService(BaseService):
    name = "ftp"
    ports = [21]
    default_image = "build"

    def compose_fragment(self, decky_name: str, log_target: str | None = None, service_cfg: dict | None = None) -> dict:
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-ftp",
            "restart": "unless-stopped",
            "environment": {
                "NODE_NAME": decky_name,
            },
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
