# SPDX-License-Identifier: AGPL-3.0-or-later
"""DECNET SWARM — multihost deployment subsystem.

Components:
* ``pki``          — X.509 CA + CSR signing used by all swarm mTLS channels
* ``client``       — master-side HTTP client that talks to remote workers
* ``log_forwarder``— worker-side syslog-over-TLS (RFC 5425) forwarder
"""
