"""
Shared pytest configuration.

Env vars required by decnet.env must be set here, at module level, before
any test file imports decnet.* — pytest loads conftest.py first.
"""
import os

os.environ.setdefault("DECNET_JWT_SECRET", "test-jwt-secret-not-for-production-use")
# Expose OpenAPI schema so schemathesis can load it during tests
os.environ.setdefault("DECNET_DEVELOPER", "true")
