"""
Service plugin registry.

Auto-discovers all BaseService subclasses by importing every module in the
services package. Adding a new service requires nothing beyond dropping a
new .py file here that subclasses BaseService.
"""

import importlib
import pkgutil
from pathlib import Path

from decnet.services.base import BaseService

_registry: dict[str, BaseService] = {}
_loaded = False


def _load_plugins() -> None:
    global _loaded
    if _loaded:
        return
    package_dir = Path(__file__).parent
    for module_info in pkgutil.iter_modules([str(package_dir)]):
        if module_info.name in ("base", "registry"):
            continue
        importlib.import_module(f"decnet.services.{module_info.name}")
    for cls in BaseService.__subclasses__():
        instance = cls()
        _registry[instance.name] = instance
    _loaded = True


def get_service(name: str) -> BaseService:
    _load_plugins()
    if name not in _registry:
        raise KeyError(f"Unknown service: '{name}'. Available: {list(_registry)}")
    return _registry[name]


def all_services() -> dict[str, BaseService]:
    _load_plugins()
    return dict(_registry)
