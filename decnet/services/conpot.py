from decnet.services.base import BaseService


class ConpotService(BaseService):
    """ICS/SCADA honeypot covering Modbus (502), SNMP (161 UDP), and HTTP (80).

    Uses the official honeynet/conpot image which ships a default ICS profile
    that emulates a Siemens S7-200 PLC.
    """

    name = "conpot"
    ports = [502, 161, 80]
    default_image = "honeynet/conpot"

    def compose_fragment(self, decky_name: str, log_target: str | None = None, service_cfg: dict | None = None) -> dict:
        return {
            "image": "honeynet/conpot",
            "container_name": f"{decky_name}-conpot",
            "restart": "unless-stopped",
            "environment": {
                "CONPOT_TEMPLATE": "default",
            },
        }

    def dockerfile_context(self):
        return None
