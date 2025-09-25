from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from capabilities import REGISTRY
from evidence.store import EvidenceStore, get_default_store
from graph import GraphAdapter, get_default_graph
from investigation_adapter import PersistentInvestigationStore
from planner import Plan, PlannedTask, Planner

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    task_id: str
    success: bool
    error: Optional[str]
    produced_entities: List[Dict[str, Any]]
    produced_relationships: List[Dict[str, Any]]
    evidence_ids: List[str]


class ExecutionEngine:
    """Lightweight sequential execution engine for planned capability tasks.

    Responsibilities:
      * Load persisted plan (via store helper)
      * Identify runnable tasks (all dependencies completed)
      * Execute capability (sync or async) in thread if blocking
      * Persist evidence artifacts for raw metrics/debug (optional placeholder)
      * Update in-memory graph with produced entities & relationships
      * Update task status -> running/completed/failed and persist plan
      * Broadcast WebSocket events via provided callback
    """

    def __init__(
        self,
        store: PersistentInvestigationStore,
        graph: Optional[GraphAdapter] = None,
        evidence: Optional[EvidenceStore] = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.store = store
        self.graph = graph or get_default_graph()
        self.evidence = evidence or get_default_store()
        self.on_event = on_event
        self._planner = Planner()

    # ---------------- Plan Helpers -----------------
    def _load_plan(self, inv_id: str):
        # Access adapter internal helper (best-effort) else rebuild
        if hasattr(self.store, '_plan_file'):
            inv = self.store._items.get(inv_id)  # type: ignore[attr-defined]
            if not inv:
                raise ValueError('Investigation not found')
            if hasattr(self.store, '_load_or_build_plan'):
                return self.store._load_or_build_plan(inv)  # type: ignore
        # Fallback reconstruct minimal plan
        inv_dict = None
        # Use public API to fetch details (sync risk minimal for internal call)
        # This engine runs inside event loop; we assume details already cached
        for k, v in getattr(self.store, '_items', {}).items():  # type: ignore
            if k == inv_id:
                inv_dict = v.to_dict()
        if not inv_dict:
            raise ValueError('Investigation not found')
        return self._planner.build_plan(inv_id, inv_dict['investigation_type'], inv_dict['targets'])

    def _persist_plan(self, plan: Plan):
        if hasattr(self.store, '_persist_plan'):
            try:
                self.store._persist_plan(plan.investigation_id, plan)  # type: ignore[attr-defined]
            except Exception as e:  # pragma: no cover
                logger.error(f"Persist plan failed: {e}")

    # ---------------- Execution -----------------
    async def run_next_task(self, investigation_id: str) -> Optional[ExecutionResult]:
        plan = self._load_plan(investigation_id)
        # Find next runnable
        runnable = [t for t in plan.tasks.values() if t.status == 'planned' and all(plan.tasks[d].status == 'completed' for d in t.depends_on)]
        if not runnable:
            return None
        # Simple selection: pick lowest risk/cost ordering proxy
        def risk_rank(cap_id: str) -> int:
            rl = REGISTRY[cap_id].risk_level
            return {'low': 0, 'medium': 1, 'high': 2}.get(rl, 1)
        runnable.sort(key=lambda t: (risk_rank(t.capability_id), REGISTRY[t.capability_id].cost_weight))
        task = runnable[0]
        task.status = 'running'
        self._persist_plan(plan)
        self._emit('task_started', investigation_id, task)
        cap_def = REGISTRY[task.capability_id]
        context = {"investigation_id": investigation_id}
        try:
            exec_fn = cap_def.execute
            if exec_fn is None:
                raise RuntimeError('Capability has no execute function')
            # Support sync or async
            if inspect.iscoroutinefunction(exec_fn):
                result = await exec_fn(context, **task.inputs)
            else:
                # Offload blocking call
                result = await asyncio.to_thread(exec_fn, context, **task.inputs)
            evidence_ids: List[str] = []
            # Persist a lightweight evidence record for metrics if present
            if result.metrics:
                rec = self.evidence.save(
                    data=str(result.metrics),
                    investigation_id=investigation_id,
                    capability_id=task.capability_id,
                    artifact_type='metrics',
                    mime_type='text/plain',
                    source='execution-engine',
                    tags={"capability": task.capability_id},
                    suggested_name=f"{task.capability_id}_metrics.txt"
                )
                evidence_ids.append(rec.evidence_id)
            # Graph updates
            for ent in result.produced_entities:
                etype = ent.get('type') or 'entity'
                key = ent.get('value') or ent.get('domain') or ent.get('subject') or str(hash(frozenset(ent.items())))
                props = {k: v for k, v in ent.items() if k not in ('type','value')}
                self.graph.upsert_entity(etype, key, props)
            for rel in result.produced_relationships:
                try:
                    source = rel.get('source')  # expected (type,key)
                    target = rel.get('target')
                    rel_type = rel.get('type') or 'RELATED_TO'
                    if isinstance(source, (list, tuple)) and isinstance(target, (list, tuple)):
                        self.graph.link(tuple(source), tuple(target), rel_type, {})
                except Exception as e:  # pragma: no cover
                    logger.warning(f"Relationship add failed: {e}")
            task.status = 'completed' if result.success else 'failed'
            self._persist_plan(plan)
            self._emit('task_completed' if result.success else 'task_failed', investigation_id, task)
            return ExecutionResult(
                task_id=task.id,
                success=result.success,
                error=result.error,
                produced_entities=result.produced_entities,
                produced_relationships=result.produced_relationships,
                evidence_ids=evidence_ids,
            )
        except Exception as e:
            task.status = 'failed'
            self._persist_plan(plan)
            self._emit('task_failed', investigation_id, task, extra={"error": str(e)})
            logger.error(f"Execution failed for {task.capability_id}: {e}")
            return ExecutionResult(task_id=task.id, success=False, error=str(e), produced_entities=[], produced_relationships=[], evidence_ids=[])

    async def run_all(self, investigation_id: str):
        while True:
            res = await self.run_next_task(investigation_id)
            if res is None:
                break

    # ---------------- Events -----------------
    def _emit(self, event_type: str, investigation_id: str, task: PlannedTask, extra: Optional[Dict[str, Any]] = None):
        if not self.on_event:
            return
        payload = {
            "event": event_type,
            "investigation_id": investigation_id,
            "task_id": task.id,
            "capability_id": task.capability_id,
            "status": task.status,
        }
        if extra:
            payload.update(extra)
        try:
            self.on_event(event_type, payload)
        except Exception as e:  # pragma: no cover
            logger.error(f"Event callback error: {e}")


# ---------------- Evidence Provenance (Merkle) -----------------

def merkle_root_hash(hashes: List[str]) -> Optional[str]:
    if not hashes:
        return None
    layer = hashes[:]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i+1] if i+1 < len(layer) else a
            import hashlib
            nxt.append(hashlib.sha256((a + b).encode('utf-8')).hexdigest())
        layer = nxt
    return layer[0]

def compute_investigation_provenance(store: EvidenceStore, investigation_id: str) -> Dict[str, Any]:
    # Collect evidence hashes for this investigation (deterministic ordering)
    records = [r for r in store.iter_records() if r.investigation_id == investigation_id]
    records.sort(key=lambda r: r.sha256)
    leaves = [r.sha256 for r in records]
    root = merkle_root_hash(leaves) if leaves else None
    return {
        "investigation_id": investigation_id,
        "leaf_count": len(leaves),
        "merkle_root": root,
        "leaves": leaves,
    }
