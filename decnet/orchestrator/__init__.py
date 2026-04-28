"""DECNET orchestrator — synthetic life-injection worker.

Drives realistic-looking activity between deckies (inter-decky traffic and
in-decky filesystem mutations) so the honeypot stops looking suspiciously
static.  Sole writer of the ``OrchestratorEvent`` table.
"""
from decnet.orchestrator.worker import orchestrator_worker

__all__ = ["orchestrator_worker"]
