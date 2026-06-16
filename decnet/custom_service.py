# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Bring-your-own-service (BYOS) support.

CustomService wraps a user-defined service from an INI [custom-*] section.
It is instantiated dynamically and registered via register_custom_service(),
not through the auto-discovery mechanism in the registry.
"""

from decnet.services.base import BaseService


class CustomService(BaseService):
    """A user-defined service that runs an arbitrary Docker image."""

    def __init__(self, name: str, image: str, exec_cmd: str, ports: list[int] | None = None):
        self.name = name
        self.default_image = image
        self.ports = ports or []
        self._exec_cmd = exec_cmd

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        slug = self.name.replace("_", "-")
        fragment: dict = {
            "image": self.default_image,
            "container_name": f"{decky_name}-{slug}",
            "restart": "unless-stopped",
            "environment": {"NODE_NAME": decky_name},
        }
        if self._exec_cmd:
            fragment["command"] = self._exec_cmd.split()
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        return fragment

    def dockerfile_context(self):
        return None
