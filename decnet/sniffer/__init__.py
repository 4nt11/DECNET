# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Fleet-wide MACVLAN sniffer microservice.

Runs as a single host-side background task (not per-decky) that sniffs
all TLS traffic on the MACVLAN interface, extracts fingerprints, and
feeds events into the existing log pipeline.
"""

from decnet.sniffer.worker import sniffer_worker

__all__ = ["sniffer_worker"]
