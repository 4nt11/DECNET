# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Service plugin registry.

Auto-discovers all BaseService subclasses by importing every module in the
services package. Adding a new service requires nothing beyond dropping a
new .py file here that subclasses BaseService.

Professional-tier honeypots live in the optional ``decnet.services.pro``
subpackage, which ships only in the Professional build (a private tree merged
in at packaging time) and is absent from the open-core Community build. The
registry scans it when present, so absence of the directory IS the entitlement
gate — no licence check, no feature flag.
"""

import importlib
import pkgutil
from pathlib import Path

from decnet.services.base import BaseService

_registry: dict[str, BaseService] = {}
_loaded = False


def _all_subclasses(cls: type) -> set[type]:
    # Recurse: a pro honeypot may extend a community service, not BaseService
    # directly, and __subclasses__() only returns direct children.
    subs = set(cls.__subclasses__())
    return subs.union(*(_all_subclasses(s) for s in subs))


def _load_plugins() -> None:
    global _loaded
    if _loaded:
        return
    package_dir = Path(__file__).parent
    for module_info in pkgutil.iter_modules([str(package_dir)]):
        if module_info.name in ("base", "registry"):
            continue
        importlib.import_module(f"decnet.services.{module_info.name}")
    # Professional build only: present == entitled. Community build has no pro/.
    pro_dir = package_dir / "pro"
    if pro_dir.is_dir():
        for mi in pkgutil.iter_modules([str(pro_dir)]):
            importlib.import_module(f"decnet.services.pro.{mi.name}")
    for cls in _all_subclasses(BaseService):
        if not cls.__module__.startswith("decnet.services."):
            continue
        instance = cls()  # type: ignore[abstract]
        _registry[instance.name] = instance
    _loaded = True


def register_custom_service(instance: BaseService) -> None:
    """Register a dynamically created service (e.g. BYOS from INI)."""
    _load_plugins()
    _registry[instance.name] = instance


def get_service(name: str) -> BaseService:
    _load_plugins()
    if name not in _registry:
        raise KeyError(f"Unknown service: '{name}'. Available: {list(_registry)}")
    return _registry[name]


def all_services() -> dict[str, BaseService]:
    _load_plugins()
    return dict(_registry)
