"""Vector store substrate for behavioral fingerprint similarity search.

Provider-pluggable storage for ``(kind, id, vector)`` triples used by the
future statistical re-identification engine. ``kind`` discriminates
feature families (``ja3``, ``hassh``, ``keystroke``, ``cmd_ngram``, ...)
so new feature types are additive — no schema migration required when
adding a new extractor.

Use :func:`get_vectorstore` from :mod:`decnet.vectorstore.factory`; never
import concrete implementations directly. Mirrors the same factory
discipline as :mod:`decnet.bus` and :mod:`decnet.web.db`.
"""
from decnet.vectorstore.base import (
    BaseVectorStore,
    Neighbor,
    VectorRecord,
    VECTORSTORE_SCHEMA_VERSION,
)
from decnet.vectorstore.factory import get_vectorstore

__all__ = [
    "BaseVectorStore",
    "Neighbor",
    "VectorRecord",
    "VECTORSTORE_SCHEMA_VERSION",
    "get_vectorstore",
]
