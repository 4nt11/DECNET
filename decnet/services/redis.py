from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "redis"


class RedisService(BaseService):
    name = "redis"
    ports = [6379]
    default_image = "build"

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
