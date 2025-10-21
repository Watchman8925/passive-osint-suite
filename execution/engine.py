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
from core.investigation_tracker import get_investigation_tracker
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
        if hasattr(self.store, "_plan_file"):
            inv = self.store._items.get(inv_id)  # type: ignore[attr-defined]
            if not inv:
                raise ValueError("Investigation not found")
            if hasattr(self.store, "_load_or_build_plan"):
                return self.store._load_or_build_plan(inv)  # type: ignore
        # Fallback reconstruct minimal plan
        inv_dict = None
        # Use public API to fetch details (sync risk minimal for internal call)
        # This engine runs inside event loop; we assume details already cached
        for k, v in getattr(self.store, "_items", {}).items():  # type: ignore
            if k == inv_id:
                inv_dict = v.to_dict()
        if not inv_dict:
            raise ValueError("Investigation not found")
        return self._planner.build_plan(
            inv_id, inv_dict["investigation_type"], inv_dict["targets"]
        )

    def _persist_plan(self, plan: Plan):
        if hasattr(self.store, "_persist_plan"):
            try:
                self.store._persist_plan(plan.investigation_id, plan)  # type: ignore[attr-defined]
            except Exception as e:  # pragma: no cover
                logger.error(f"Persist plan failed: {e}")

    # ---------------- Execution -----------------
    async def run_next_task(self, investigation_id: str) -> Optional[ExecutionResult]:
        plan = self._load_plan(investigation_id)
        # Find next runnable
        runnable = [
            t
            for t in plan.tasks.values()
            if t.status == "planned"
            and all(plan.tasks[d].status == "completed" for d in t.depends_on)
        ]
        if not runnable:
            return None

        # Simple selection: pick lowest risk/cost ordering proxy
        def risk_rank(cap_id: str) -> int:
            rl = REGISTRY[cap_id].risk_level
            return {"low": 0, "medium": 1, "high": 2}.get(rl, 1)

        runnable.sort(
            key=lambda t: (
                risk_rank(t.capability_id),
                REGISTRY[t.capability_id].cost_weight,
            )
        )
        task = runnable[0]
        task.status = "running"
        self._persist_plan(plan)
        self._emit("task_started", investigation_id, task)
        cap_def = REGISTRY[task.capability_id]
        context = {"investigation_id": investigation_id}
        try:
            exec_fn = cap_def.execute
            if exec_fn is None:
                raise RuntimeError("Capability has no execute function")
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
                    artifact_type="metrics",
                    mime_type="text/plain",
                    source="execution-engine",
                    tags={"capability": task.capability_id},
                    suggested_name=f"{task.capability_id}_metrics.txt",
                )
                evidence_ids.append(rec.evidence_id)
            # Graph updates
            try:
                tracker = get_investigation_tracker()
            except Exception:
                tracker = None
            tracker_finding_ids: List[str] = []
            for ent in result.produced_entities:
                etype = ent.get("type") or "entity"
                key = (
                    ent.get("value")
                    or ent.get("domain")
                    or ent.get("subject")
                    or str(hash(frozenset(ent.items())))
                )
                props = {k: v for k, v in ent.items() if k not in ("type", "value")}
                existing = self.graph.get_entity(etype, key)
                investigation_ids = []
                if existing:
                    existing_props = existing.properties or {}
                    existing_ids = existing_props.get("investigation_ids")
                    if isinstance(existing_ids, (list, tuple, set)):
                        investigation_ids.extend(str(i) for i in existing_ids)
                    else:
                        legacy_id = existing_props.get("investigation_id")
                        if legacy_id:
                            investigation_ids.append(str(legacy_id))
                if investigation_id not in investigation_ids:
                    investigation_ids.append(investigation_id)
                props["investigation_ids"] = sorted(set(investigation_ids))
                self.graph.upsert_entity(etype, key, props)
                if tracker:
                    value = ent.get("value") or ent.get("domain") or ent.get("subject")
                    if value is None:
                        continue
                    try:
                        confidence = float(ent.get("confidence", 0.6))
                    except (TypeError, ValueError):
                        confidence = 0.6
                    confidence = max(0.0, min(confidence, 1.0))
                    metadata = {k: v for k, v in ent.items() if k != "type"}
                    metadata["task_id"] = task.id
                    metadata["investigation_id"] = investigation_id
                    try:
                        fid = tracker.add_finding(
                            investigation_id=investigation_id,
                            finding_type=str(etype),
                            value=str(value),
                            source_module=task.capability_id or "unknown",
                            confidence=confidence,
                            metadata=metadata,
                        )
                        if fid:
                            tracker_finding_ids.append(fid)
                    except Exception as tracker_error:  # pragma: no cover - tracker best-effort
                        logger.debug(f"Tracker add finding failed: {tracker_error}")
            for rel in result.produced_relationships:
                try:
                    source = rel.get("source")  # expected (type,key)
                    target = rel.get("target")
                    rel_type = rel.get("type") or "RELATED_TO"
                    if isinstance(source, (list, tuple)) and isinstance(
                        target, (list, tuple)
                    ):
                        rel_props = dict(rel.get("properties", {}))
                        rel_props.setdefault("investigation_id", investigation_id)
                        self.graph.link(tuple(source), tuple(target), rel_type, rel_props)
                except Exception as e:  # pragma: no cover
                    logger.warning(f"Relationship add failed: {e}")
            task.status = "completed" if result.success else "failed"
            self._persist_plan(plan)
            self._emit(
                "task_completed" if result.success else "task_failed",
                investigation_id,
                task,
            )
            exec_result = ExecutionResult(
                task_id=task.id,
                success=result.success,
                error=result.error,
                produced_entities=result.produced_entities,
                produced_relationships=result.produced_relationships,
                evidence_ids=evidence_ids,
            )
            if hasattr(self.store, "record_task_output"):
                try:
                    await self.store.record_task_output(
                        investigation_id=investigation_id,
                        capability_id=task.capability_id or "unknown",
                        task_id=task.id,
                        success=result.success,
                        produced_entities=result.produced_entities,
                        produced_relationships=result.produced_relationships,
                        evidence_ids=evidence_ids,
                        findings=tracker_finding_ids,
                        error=result.error,
                    )
                except Exception as store_error:  # pragma: no cover - persistence best effort
                    logger.error(f"Failed to persist task output: {store_error}")
            return exec_result
        except Exception as e:
            task.status = "failed"
            self._persist_plan(plan)
            self._emit("task_failed", investigation_id, task, extra={"error": str(e)})
            logger.error(f"Execution failed for {task.capability_id}: {e}")
            exec_result = ExecutionResult(
                task_id=task.id,
                success=False,
                error=str(e),
                produced_entities=[],
                produced_relationships=[],
                evidence_ids=[],
            )
            if hasattr(self.store, "record_task_output"):
                try:
                    await self.store.record_task_output(
                        investigation_id=investigation_id,
                        capability_id=task.capability_id or "unknown",
                        task_id=task.id,
                        success=False,
                        produced_entities=[],
                        produced_relationships=[],
                        evidence_ids=[],
                        findings=[],
                        error=str(e),
                    )
                except Exception as store_error:  # pragma: no cover
                    logger.error(f"Failed to persist failed task output: {store_error}")
            return exec_result

    async def run_all(self, investigation_id: str):
        while True:
            res = await self.run_next_task(investigation_id)
            if res is None:
                break

    # ---------------- Events -----------------
    def _emit(
        self,
        event_type: str,
        investigation_id: str,
        task: PlannedTask,
        extra: Optional[Dict[str, Any]] = None,
    ):
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
            b = layer[i + 1] if i + 1 < len(layer) else a
            import hashlib

            nxt.append(hashlib.sha256((a + b).encode("utf-8")).hexdigest())
        layer = nxt
    return layer[0]


def compute_investigation_provenance(
    store: EvidenceStore, investigation_id: str
) -> Dict[str, Any]:
    # Collect evidence hashes for this investigation (deterministic ordering)
    records = [
        r for r in store.iter_records() if r.investigation_id == investigation_id
    ]
    records.sort(key=lambda r: r.sha256)
    leaves = [r.sha256 for r in records]
    root = merkle_root_hash(leaves) if leaves else None
    return {
        "investigation_id": investigation_id,
        "leaf_count": len(leaves),
        "merkle_root": root,
        "leaves": leaves,
    }
