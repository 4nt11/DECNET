"""Built-in canary generators (synthesised fake artifacts).

Concrete classes live in sibling modules and are imported lazily by
:func:`decnet.canary.factory.get_generator` to keep the import-time
cost of :mod:`decnet.canary` cheap for callers that only need the
ABCs.
"""
