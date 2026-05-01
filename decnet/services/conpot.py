from pathlib import Path
from decnet.services.base import BaseService


class ConpotService(BaseService):
    """ICS/SCADA honeypot covering Modbus (502), SNMP (161 UDP), and HTTP (80).

    Uses a custom build context wrapping the official honeynet/conpot image
    to fix Modbus binding to port 502.
    """

    name = "conpot"
    ports = [502, 161, 80]
    default_image = "build"
    # config_schema: no user-tunable fields yet — TODO add when compose_fragment grows cfg reads

    def compose_fragment(self, decky_name: str, log_target: str | None = None, service_cfg: dict | None = None) -> dict:
        env = {
            "CONPOT_TEMPLATE": "default",
            "NODE_NAME": decky_name,
        }
        if log_target:
            env["LOG_TARGET"] = log_target

        return {
            "build": {
                "context": str(self.dockerfile_context()),
                "args": {"BASE_IMAGE": "honeynet/conpot:latest"},
            },
            "container_name": f"{decky_name}-conpot",
            "restart": "unless-stopped",
            "environment": env,
        }

    def dockerfile_context(self):
        return Path(__file__).parent.parent / "templates" / "conpot"
