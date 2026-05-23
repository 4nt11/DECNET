# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
from decnet.services.base import BaseService, ServiceConfigField

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "redis"


class RedisService(BaseService):
    name = "redis"
    ports = [6379]
    default_image = "build"

    config_schema = [
        ServiceConfigField(
            key="version",
            label="Advertised Redis version",
            type="string",
            placeholder="7.2.4",
            help="Reported by INFO server -> redis_version.",
        ),
        ServiceConfigField(
            key="os_string",
            label="Advertised OS string",
            type="string",
            placeholder="Linux 5.15.0 x86_64",
            help="Reported by INFO server -> os.",
        ),
    ]

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        cfg = service_cfg or {}
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-redis",
            "restart": "unless-stopped",
            "environment": {"NODE_NAME": decky_name},
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        if "version" in cfg:
            fragment["environment"]["REDIS_VERSION"] = cfg["version"]
        if "os_string" in cfg:
            fragment["environment"]["REDIS_OS"] = cfg["os_string"]
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
