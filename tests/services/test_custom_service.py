"""
Tests for decnet.custom_service — BYOS (bring-your-own-service) support.
"""
from decnet.custom_service import CustomService


class TestCustomServiceComposeFragment:
    def _svc(self, name="my-tool", image="myrepo/mytool:latest",
             exec_cmd="", ports=None):
        return CustomService(name=name, image=image,
                             exec_cmd=exec_cmd, ports=ports)

    def test_basic_fragment_structure(self):
        svc = self._svc()
        frag = svc.compose_fragment("decky-01")
        assert frag["image"] == "myrepo/mytool:latest"
        assert frag["container_name"] == "decky-01-my-tool"
        assert frag["restart"] == "unless-stopped"
        assert frag["environment"]["NODE_NAME"] == "decky-01"

    def test_underscores_in_name_become_dashes(self):
        svc = self._svc(name="my_custom_tool")
        frag = svc.compose_fragment("decky-01")
        assert frag["container_name"] == "decky-01-my-custom-tool"

    def test_exec_cmd_is_split_into_list(self):
        svc = self._svc(exec_cmd="/usr/bin/server --port 8080")
        frag = svc.compose_fragment("decky-01")
        assert frag["command"] == ["/usr/bin/server", "--port", "8080"]

    def test_empty_exec_cmd_omits_command_key(self):
        svc = self._svc(exec_cmd="")
        frag = svc.compose_fragment("decky-01")
        assert "command" not in frag

    def test_log_target_injected_into_environment(self):
        svc = self._svc()
        frag = svc.compose_fragment("decky-01", log_target="10.0.0.5:5140")
        assert frag["environment"]["LOG_TARGET"] == "10.0.0.5:5140"

    def test_no_log_target_omits_key(self):
        svc = self._svc()
        frag = svc.compose_fragment("decky-01", log_target=None)
        assert "LOG_TARGET" not in frag["environment"]

    def test_service_cfg_is_accepted_without_error(self):
        svc = self._svc()
        # service_cfg is accepted but not used by CustomService
        frag = svc.compose_fragment("decky-01", service_cfg={"key": "val"})
        assert frag is not None

    def test_ports_stored_on_instance(self):
        svc = CustomService("tool", "img", "", ports=[8080, 9090])
        assert svc.ports == [8080, 9090]

    def test_no_ports_defaults_to_empty_list(self):
        svc = CustomService("tool", "img", "")
        assert svc.ports == []


class TestCustomServiceDockerfileContext:
    def test_returns_none(self):
        svc = CustomService("tool", "img", "cmd")
        assert svc.dockerfile_context() is None
