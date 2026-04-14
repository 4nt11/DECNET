from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates" / "sniffer"


class SnifferService(BaseService):
    """
    Passive network sniffer deployed alongside deckies on the MACVLAN.

    Captures TLS handshakes in promiscuous mode and extracts JA3/JA3S hashes
    plus connection metadata. Requires NET_RAW + NET_ADMIN capabilities.
    No inbound ports — purely passive.
    """

    name = "sniffer"
    ports: list[int] = []
    default_image = "build"
    fleet_singleton = True

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-sniffer",
            "restart": "unless-stopped",
            "cap_add": ["NET_RAW", "NET_ADMIN"],
            "environment": {
                "NODE_NAME": decky_name,
            },
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
