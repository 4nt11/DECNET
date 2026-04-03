from decnet.services.base import BaseService


class SSHService(BaseService):
    name = "ssh"
    ports = [22, 2222]
    default_image = "cowrie/cowrie"

    def compose_fragment(self, decky_name: str, log_target: str | None = None) -> dict:
        env: dict = {
            # Override [honeypot] and [ssh] listen_endpoints to also bind port 22
            "COWRIE_HONEYPOT_HOSTNAME": decky_name,
            "COWRIE_HONEYPOT_LISTEN_ENDPOINTS": "tcp:22:interface=0.0.0.0 tcp:2222:interface=0.0.0.0",
            "COWRIE_SSH_LISTEN_ENDPOINTS": "tcp:22:interface=0.0.0.0 tcp:2222:interface=0.0.0.0",
        }
        if log_target:
            host, port = log_target.rsplit(":", 1)
            env["COWRIE_OUTPUT_TCP_ENABLED"] = "true"
            env["COWRIE_OUTPUT_TCP_HOST"] = host
            env["COWRIE_OUTPUT_TCP_PORT"] = port
        return {
            "image": "cowrie/cowrie",
            "container_name": f"{decky_name}-ssh",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": env,
        }

    def dockerfile_context(self):
        return None
