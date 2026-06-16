# SPDX-License-Identifier: AGPL-3.0-or-later
"""
DECNET-PROBER — standalone active network probing service.

Runs as a detached host-level process (no container). Sends crafted TLS
probes to discover C2 frameworks and other attacker infrastructure via
JARM fingerprinting. Results are written as RFC 5424 syslog + JSON to the
same log file the collector uses, so the existing ingestion pipeline picks
them up automatically.
"""

from decnet.prober.worker import prober_worker

__all__ = ["prober_worker"]
