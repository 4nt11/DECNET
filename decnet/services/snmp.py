from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates" / "snmp"


class SNMPService(BaseService):
    name = "snmp"
    ports = [161]
    default_image = "build"

    def compose_fragment(self, decky_name: str, log_target: str | None = None) -> dict:
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-snmp",
            "restart": "unless-stopped",
            "environment": {"HONEYPOT_NAME": decky_name},
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
