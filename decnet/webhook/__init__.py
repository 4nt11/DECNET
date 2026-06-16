# SPDX-License-Identifier: AGPL-3.0-or-later
"""External webhook egress — ship bus events to SIEM/SOAR stacks."""
from decnet.webhook.worker import webhook_worker

__all__ = ["webhook_worker"]
