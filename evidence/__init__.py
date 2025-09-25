"""Evidence store package.

The evidence model focuses on immutable raw artifacts plus a small metadata envelope.
Future enhancements: object storage backend abstraction, Merkle chaining, retention policies.
"""
from .store import EvidenceRecord, EvidenceStore, get_default_store  # noqa
