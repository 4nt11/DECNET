"""TTP-tagging subsystem.

Maps DECNET telemetry to MITRE ATT&CK technique tags. See
``development/TTP_TAGGING.md`` for the full design. Callers obtain
the active tagger via :func:`decnet.ttp.factory.get_tagger` — never
instantiate concrete lifter classes directly.
"""
