from decnet.services.base import BaseService


class SMTPService(BaseService):
    name = "smtp"
    ports = [25, 587]
    default_image = "dtagdevsec/mailoney"

    def compose_fragment(self, decky_name: str, log_target: str | None = None) -> dict:
        env: dict = {
            "MAILONEY_HOSTNAME": decky_name,
            "MAILONEY_PORTS": "25,587",
        }
        if log_target:
            env["MAILONEY_LOG_TARGET"] = log_target
        return {
            "image": "dtagdevsec/mailoney",
            "container_name": f"{decky_name}-smtp",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": env,
        }

    def dockerfile_context(self):
        return None
