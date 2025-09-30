"""In-memory graph adapter (initial stub).

Interface goals:
- upsert_entity(entity_type, key, properties)
- link(source, target, rel_type, properties)
- get_entity(entity_type, key)
- neighbors(entity_type, key, rel_type=None)
- export_snapshot()

Later: replace implementation with Neo4j / other backend without changing callers.
"""

from .adapter import GraphAdapter, get_default_graph  # noqa
