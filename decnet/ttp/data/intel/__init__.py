# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-provider intel-signal → ATT&CK technique mapping data.

One YAML file per intel provider (abuseipdb / greynoise / feodo /
threatfox), structured per the schema in
:mod:`decnet.ttp.data.intel_loader`. Each entry carries a STIX-shaped
``external_reference`` so the future STIX/MISP exporter can emit
relationship objects without a second mapping pass.
"""
