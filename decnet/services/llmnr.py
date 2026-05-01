from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "llmnr"


class LLMNRService(BaseService):
    """LLMNR/mDNS/NBNS poisoning detector.

    Listens on UDP 5355 (LLMNR) and UDP 5353 (mDNS) and logs any
    name-resolution queries it receives — a strong indicator of an attacker
    running Responder or similar tools on the LAN.
    """

    name = "llmnr"
    ports = [5355, 5353]
    default_image = "build"
    # config_schema: no user-tunable fields yet — TODO add when compose_fragment grows cfg reads

    def compose_fragment(self, decky_name: str, log_target: str | None = None, service_cfg: dict | None = None) -> dict:
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-llmnr",
            "restart": "unless-stopped",
            "environment": {"NODE_NAME": decky_name},
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
