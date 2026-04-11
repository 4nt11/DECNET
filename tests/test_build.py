"""Smoke test: verify the package and all submodules import cleanly."""
import importlib
import pytest


MODULES = [
    "decnet",
    "decnet.cli",
    "decnet.config",
    "decnet.composer",
    "decnet.deployer",
    "decnet.network",
    "decnet.archetypes",
    "decnet.distros",
    "decnet.os_fingerprint",
    "decnet.ini_loader",
    "decnet.custom_service",
    "decnet.correlation",
    "decnet.correlation.engine",
    "decnet.correlation.graph",
    "decnet.correlation.parser",
    "decnet.logging",
    "decnet.logging.file_handler",
    "decnet.logging.forwarder",
    "decnet.logging.syslog_formatter",
    "decnet.services",
    "decnet.services.registry",
    "decnet.services.base",
    "decnet.services.ssh",
    "decnet.services.ftp",
    "decnet.services.http",
    "decnet.services.smb",
    "decnet.services.rdp",
    "decnet.services.smtp",
    "decnet.services.mysql",
    "decnet.services.postgres",
    "decnet.services.redis",
    "decnet.services.mongodb",
    "decnet.services.mssql",
    "decnet.services.elasticsearch",
    "decnet.services.ldap",
    "decnet.services.k8s",
    "decnet.services.docker_api",
    "decnet.services.vnc",
    "decnet.services.telnet",
    "decnet.services.tftp",
    "decnet.services.snmp",
    "decnet.services.sip",
    "decnet.services.mqtt",
    "decnet.services.llmnr",
    "decnet.services.imap",
    "decnet.services.pop3",
    "decnet.services.conpot",
    "decnet.services.registry",
]


@pytest.mark.parametrize("module", MODULES)
def test_module_imports(module):
    importlib.import_module(module)
