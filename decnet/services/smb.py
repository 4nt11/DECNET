# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "smb"


class SMBService(BaseService):
    name = "smb"
    ports = [445, 139]
    default_image = "build"
    # config_schema: no user-tunable fields yet — TODO add when compose_fragment grows cfg reads

    def compose_fragment(self, decky_name: str, log_target: str | None = None, service_cfg: dict | None = None) -> dict:
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-smb",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": {
                "NODE_NAME": decky_name,
            },
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
