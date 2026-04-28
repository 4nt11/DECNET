"""RIR delegated-stats provider.

Free, offline, no license: each Regional Internet Registry publishes a
daily plaintext file mapping IPv4 allocations to countries. Together the
five RIR files cover the entire assigned IPv4 space.

Direct imports of :class:`RirProvider` are discouraged — go through
:func:`decnet.geoip.factory.get_provider`.
"""
