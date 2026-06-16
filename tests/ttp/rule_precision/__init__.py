# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-rule precision suite for TTP rule pack v0.

One test module per rule cohort (command / behavioral / email / canary /
intel) drives the labelled holdout corpus through a real
:class:`RuleEngine` bound to ``./rules/ttp/`` and asserts the
Appendix-C precision target.

Live cohort: command (R0001-R0030). Other cohorts ship YAMLs whose
match specs target downstream lifters (E.3.9-E.3.12); their
precision tests are :pyfunc:`pytest.xfail`-gated until the lifter
lands, matching the CDD pattern from ``development/TTP_TAGGING.md``.
"""
