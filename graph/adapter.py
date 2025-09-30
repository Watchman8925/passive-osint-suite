from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

EntityKey = Tuple[str, str]  # (type, value)


@dataclass
class GraphEntity:
    type: str
    key: str
    properties: Dict[str, Any]
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class GraphEdge:
    rel_type: str
    source: EntityKey
    target: EntityKey
    properties: Dict[str, Any]
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class GraphAdapter:
    def __init__(self):
        self._entities: Dict[EntityKey, GraphEntity] = {}
        self._edges: List[GraphEdge] = []
        self._lock = threading.RLock()

    # Entity Operations
    def upsert_entity(
        self, entity_type: str, key: str, properties: Dict[str, Any]
    ) -> GraphEntity:
        ek = (entity_type, key)
        with self._lock:
            if ek in self._entities:
                ent = self._entities[ek]
                ent.properties.update(properties)
                ent.updated_at = time.time()
            else:
                ent = GraphEntity(
                    type=entity_type, key=key, properties=dict(properties)
                )
                self._entities[ek] = ent
            return ent

    def get_entity(self, entity_type: str, key: str) -> Optional[GraphEntity]:
        return self._entities.get((entity_type, key))

    # Edge Operations
    def link(
        self,
        source: EntityKey,
        target: EntityKey,
        rel_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> GraphEdge:
        properties = properties or {}
        with self._lock:
            edge = GraphEdge(
                rel_type=rel_type,
                source=source,
                target=target,
                properties=dict(properties),
            )
            self._edges.append(edge)
            return edge

    def neighbors(
        self,
        entity_type: str,
        key: str,
        rel_type: Optional[str] = None,
        direction: str = "both",
    ) -> Iterable[GraphEdge]:
        ek = (entity_type, key)
        for edge in self._edges:
            if rel_type and edge.rel_type != rel_type:
                continue
            if direction in ("out", "both") and edge.source == ek:
                yield edge
            if direction in ("in", "both") and edge.target == ek:
                yield edge

    def export_snapshot(self) -> Dict[str, Any]:
        return {
            "entities": [
                {
                    "type": e.type,
                    "key": e.key,
                    "properties": e.properties,
                    "created_at": e.created_at,
                    "updated_at": e.updated_at,
                }
                for e in self._entities.values()
            ],
            "edges": [
                {
                    "rel_type": ed.rel_type,
                    "source": ed.source,
                    "target": ed.target,
                    "properties": ed.properties,
                    "created_at": ed.created_at,
                    "updated_at": ed.updated_at,
                }
                for ed in self._edges
            ],
        }


_default_graph: Optional[GraphAdapter] = None


def get_default_graph() -> GraphAdapter:
    global _default_graph
    if _default_graph is None:
        _default_graph = GraphAdapter()
    return _default_graph
