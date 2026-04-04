from decnet.services.base import BaseService


class ElasticsearchService(BaseService):
    name = "elasticsearch"
    ports = [9200]
    default_image = "dtagdevsec/elasticpot"

    def compose_fragment(self, decky_name: str, log_target: str | None = None) -> dict:
        env: dict = {
            "ELASTICPOT_HOSTNAME": decky_name,
        }
        if log_target:
            env["ELASTICPOT_LOG_TARGET"] = log_target
        return {
            "image": "dtagdevsec/elasticpot",
            "container_name": f"{decky_name}-elasticsearch",
            "restart": "unless-stopped",
            "environment": env,
        }

    def dockerfile_context(self):
        return None
