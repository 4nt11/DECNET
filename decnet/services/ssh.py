from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates" / "cowrie"


class SSHService(BaseService):
    name = "ssh"
    ports = [22, 2222]
    default_image = "build"

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        cfg = service_cfg or {}
        env: dict = {
            "NODE_NAME": decky_name,
            "COWRIE_HOSTNAME": decky_name,
            "COWRIE_HONEYPOT_LISTEN_ENDPOINTS": "tcp:22:interface=0.0.0.0 tcp:2222:interface=0.0.0.0",
            "COWRIE_SSH_LISTEN_ENDPOINTS": "tcp:22:interface=0.0.0.0 tcp:2222:interface=0.0.0.0",
        }
        if log_target:
            host, port = log_target.rsplit(":", 1)
            env["COWRIE_OUTPUT_TCP_ENABLED"] = "true"
            env["COWRIE_OUTPUT_TCP_HOST"] = host
            env["COWRIE_OUTPUT_TCP_PORT"] = port

        # Optional persona overrides
        if "kernel_version" in cfg:
            env["COWRIE_HONEYPOT_KERNEL_VERSION"] = cfg["kernel_version"]
        if "kernel_build_string" in cfg:
            env["COWRIE_HONEYPOT_KERNEL_BUILD_STRING"] = cfg["kernel_build_string"]
        if "hardware_platform" in cfg:
            env["COWRIE_HONEYPOT_HARDWARE_PLATFORM"] = cfg["hardware_platform"]
        if "ssh_banner" in cfg:
            env["COWRIE_SSH_VERSION"] = cfg["ssh_banner"]
        if "users" in cfg:
            env["COWRIE_USERDB_ENTRIES"] = cfg["users"]

        return {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-ssh",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": env,
        }

    def dockerfile_context(self) -> Path:
        return TEMPLATES_DIR
