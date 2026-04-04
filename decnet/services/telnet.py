from decnet.services.base import BaseService


class TelnetService(BaseService):
    name = "telnet"
    ports = [23]
    default_image = "cowrie/cowrie"

    def compose_fragment(self, decky_name: str, log_target: str | None = None) -> dict:
        env: dict = {
            "COWRIE_HONEYPOT_HOSTNAME": decky_name,
            "COWRIE_TELNET_ENABLED": "true",
            "COWRIE_TELNET_LISTEN_ENDPOINTS": "tcp:23:interface=0.0.0.0",
            # Disable SSH so this container is telnet-only
            "COWRIE_SSH_ENABLED": "false",
        }
        if log_target:
            host, port = log_target.rsplit(":", 1)
            env["COWRIE_OUTPUT_TCP_ENABLED"] = "true"
            env["COWRIE_OUTPUT_TCP_HOST"] = host
            env["COWRIE_OUTPUT_TCP_PORT"] = port
        return {
            "image": "cowrie/cowrie",
            "container_name": f"{decky_name}-telnet",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": env,
        }

    def dockerfile_context(self):
        return None
