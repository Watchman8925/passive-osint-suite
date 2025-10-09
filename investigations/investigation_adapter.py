#!/usr/bin/env python3
"""
Investigation Adapter

Bridges the lightweight API-facing persistent investigation store with the
advanced `InvestigationManager` (task orchestration) when available.

Phase 1 Goals:
- Provide a PersistentInvestigationStore that mirrors the async interface:
  * create_investigation
  * list_investigations
  * get_investigation
  * start_investigation
  * store_ai_analysis
  * get_progress (new)
- File-backed JSON persistence to survive restarts.
- Optional integration hook to delegate orchestration to advanced manager later.

Future Extension:
- When advanced manager is activated, adapter can map lightweight records into
  the richer model and launch tasks / sync progress.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    AIOFILES_AVAILABLE = False
    logging.warning("aiofiles not installed - using synchronous file I/O (not recommended)")

from planner import Planner

try:  # Optional import; advanced orchestrator
    from investigations.investigation_manager import InvestigationManager  # type: ignore
except Exception:  # pragma: no cover
    InvestigationManager = None  # type: ignore

logger = logging.getLogger(__name__)


class SimpleStatus(str, Enum):
    created = "created"
    running = "running"
    completed = "completed"
    failed = "failed"


@dataclass
class SimpleInvestigation:
    id: str
    advanced_id: Optional[str]
    name: str
    description: Optional[str]
    targets: List[str]
    investigation_type: str
    priority: str
    tags: List[str]
    owner_id: str
    scheduled_start: Optional[datetime]
    auto_reporting: bool
    status: SimpleStatus
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    ai_analysis: Dict[str, Any]
    archived: bool

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Serialize datetimes
        for key in ["scheduled_start", "created_at", "started_at", "completed_at"]:
            val = d.get(key)
            if isinstance(val, datetime):
                d[key] = val.isoformat()
        return d

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "SimpleInvestigation":
        def parse_dt(v):
            if v is None:
                return None
            try:
                return datetime.fromisoformat(v)
            except Exception:
                return None

        return SimpleInvestigation(
            id=data["id"],
            advanced_id=data.get("advanced_id"),
            name=data.get("name", ""),
            description=data.get("description"),
            targets=data.get("targets", []),
            investigation_type=str(data.get("investigation_type") or ""),
            priority=data.get("priority", "medium"),
            tags=data.get("tags", []),
            owner_id=str(data.get("owner_id") or ""),
            scheduled_start=parse_dt(data.get("scheduled_start")),
            auto_reporting=data.get("auto_reporting", True),
            status=SimpleStatus(data.get("status", "created")),
            created_at=parse_dt(data.get("created_at")) or datetime.now(timezone.utc),
            started_at=parse_dt(data.get("started_at")),
            completed_at=parse_dt(data.get("completed_at")),
            ai_analysis=data.get("ai_analysis", {}),
            archived=data.get("archived", False),
        )


class PersistentInvestigationStore:
    """File-backed lightweight investigation store.

    Thread-safe (async) via an asyncio.Lock.
    """

    def __init__(self, storage_dir: str = "./investigation_store"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.storage_dir / "investigations.json"
        self._items: Dict[str, SimpleInvestigation] = {}
        self._lock = asyncio.Lock()
        self._load()
        self.advanced_manager: "Optional[InvestigationManager]" = None  # type: ignore
        # Reverse lookup advanced_id -> simple_id for websocket mapping
        self._adv_index = {}

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------
    def _load(self):
        """Load investigations from disk (synchronous - only called during init)"""
        if not self.index_file.exists():
            return
        try:
            data = json.loads(self.index_file.read_text())
            for item in data:
                try:
                    inv = SimpleInvestigation.from_dict(item)
                    self._items[inv.id] = inv
                except Exception as e:  # pragma: no cover
                    logger.warning(f"Skipping corrupt record: {e}")
        except Exception as e:  # pragma: no cover
            logger.error(f"Failed to load investigations: {e}")

    async def _flush(self):
        """Flush investigations to disk asynchronously"""
        try:
            serialized = [inv.to_dict() for inv in self._items.values()]
            json_data = json.dumps(serialized, indent=2)

            if AIOFILES_AVAILABLE:
                # Async file write
                async with aiofiles.open(self.index_file, 'w') as f:
                    await f.write(json_data)
            else:
                # Fallback to sync write (blocking!)
                self.index_file.write_text(json_data)
        except Exception as e:  # pragma: no cover
            logger.error(f"Failed to write investigations: {e}")

    # ------------------------------------------------------------------
    # Public API (async)
    # ------------------------------------------------------------------
    async def create_investigation(
        self,
        name: str,
        description: Optional[str],
        targets: List[str],
        investigation_type: str,
        priority: str,
        tags: List[str],
        owner_id: str,
        scheduled_start: Optional[datetime],
        auto_reporting: bool,
    ) -> str:
        async with self._lock:
            inv_id = str(uuid4())
            inv = SimpleInvestigation(
                id=inv_id,
                advanced_id=None,
                name=name,
                description=description,
                targets=targets,
                investigation_type=investigation_type,
                priority=priority,
                tags=tags or [],
                owner_id=owner_id,
                scheduled_start=scheduled_start,
                auto_reporting=auto_reporting,
                status=SimpleStatus.created,
                created_at=datetime.now(timezone.utc),
                started_at=None,
                completed_at=None,
                ai_analysis={},
                archived=False,
            )
            # Bridge: create advanced investigation if manager attached
            if self.advanced_manager:
                try:
                    # Map simple priority string to advanced enum if possible
                    adv_priority = priority
                    try:
                        if hasattr(self.advanced_manager, "Priority"):
                            # Not used; fallback
                            pass
                        else:
                            from investigation_manager import Priority as AdvPriority  # type: ignore

                            mapping = {
                                "low": AdvPriority.LOW,
                                "medium": AdvPriority.MEDIUM,
                                "high": AdvPriority.HIGH,
                                "critical": AdvPriority.CRITICAL,
                            }
                            adv_priority = mapping.get(
                                priority.lower(), AdvPriority.MEDIUM
                            )  # type: ignore
                    except Exception:  # pragma: no cover
                        pass
                    adv_id = await self.advanced_manager.create_investigation(
                        name=name,
                        description=description or "",
                        investigation_type=investigation_type,
                        targets=targets,
                        priority=adv_priority,  # mapped enum or string fallback
                        tags=tags or [],
                    )
                    inv.advanced_id = adv_id
                    self._adv_index[adv_id] = inv_id
                except Exception as e:  # pragma: no cover
                    logger.error(f"Failed to create advanced investigation mirror: {e}")
            self._items[inv_id] = inv
            await self._flush()
            return inv_id

    async def list_investigations(
        self,
        owner_id: str,
        skip: int = 0,
        limit: int = 50,
        status_filter: Optional[str] = None,
        include_archived: bool = False,
        include_meta: bool = False,
    ) -> Any:
        async with self._lock:
            items = [r for r in self._items.values() if r.owner_id == owner_id]
            if not include_archived:
                items = [r for r in items if not r.archived]
            if status_filter:
                try:
                    st = SimpleStatus(status_filter)
                    items = [r for r in items if r.status == st]
                except ValueError:
                    items = []
            total = len(items)
            items.sort(key=lambda r: r.created_at, reverse=True)
            sliced = items[skip : skip + limit]
            data = [r.to_dict() for r in sliced]
            if include_meta:
                return {
                    "items": data,
                    "meta": {"total": total, "skip": skip, "limit": limit},
                }
            return data

    async def get_investigation(
        self, investigation_id: str, owner_id: str
    ) -> Optional[Dict[str, Any]]:
        async with self._lock:
            inv = self._items.get(investigation_id)
            if not inv or inv.owner_id != owner_id:
                return None
            return inv.to_dict()

    async def start_investigation(self, investigation_id: str, owner_id: str):
        async with self._lock:
            inv = self._items.get(investigation_id)
            if not inv or inv.owner_id != owner_id:
                raise ValueError("Investigation not found or unauthorized")
            if inv.status != SimpleStatus.created:
                return
            inv.status = SimpleStatus.running
            inv.started_at = datetime.now(timezone.utc)
        await self._flush()  # Moved outside lock
        # Build an initial plan (planner integration)
        try:
            planner: Any = Planner()
            plan_builder = getattr(planner, "build_plan", None)
            if callable(plan_builder):
                plan = plan_builder(
                    investigation_id=investigation_id,
                    investigation_type=inv.investigation_type,
                    targets=inv.targets,
                )
            else:
                # Fallback to try other common method signatures dynamically
                plan = None
                for alt in ("plan", "create_plan", "build"):
                    alt_builder = getattr(planner, alt, None)
                    if callable(alt_builder):
                        try:
                            plan = alt_builder(
                                investigation_id=investigation_id,
                                investigation_type=inv.investigation_type,
                                targets=inv.targets,
                            )
                            break
                        except TypeError:
                            try:
                                plan = alt_builder(
                                    investigation_id,
                                    inv.investigation_type,
                                    inv.targets,
                                )
                                break
                            except Exception:
                                continue
                if plan is None:
                    raise AttributeError(
                        "Planner has no callable build_plan/plan/create_plan"
                    )
            self._persist_plan(investigation_id, plan)
        except Exception as e:  # pragma: no cover
            logger.error(f"Planner build failed: {e}")
        # If advanced manager exists, start orchestration outside the lock
        if self.advanced_manager and inv.advanced_id:
            try:
                # Ensure default baseline tasks exist before starting
                await self._ensure_default_tasks(inv)
                await self.advanced_manager.start_investigation(inv.advanced_id)
            except Exception as e:  # pragma: no cover
                logger.error(f"Advanced start failed for {inv.advanced_id}: {e}")

    async def store_ai_analysis(
        self, investigation_id: str, analysis_type: str, result: Dict[str, Any]
    ):
        async with self._lock:
            inv = self._items.get(investigation_id)
            if not inv:
                raise ValueError("Investigation not found")
            inv.ai_analysis[analysis_type] = result
        await self._flush()  # Moved outside lock

    async def get_progress(
        self, investigation_id: str, owner_id: str
    ) -> Dict[str, Any]:
        async with self._lock:
            inv = self._items.get(investigation_id)
            if not inv or inv.owner_id != owner_id:
                return {}
            adv_id = inv.advanced_id
        # Outside lock for advanced manager call
        if self.advanced_manager and adv_id:
            try:
                progress = await self.advanced_manager.get_investigation_progress(
                    adv_id
                )
                adv_inv = await self.advanced_manager.get_investigation(adv_id)
                # Map advanced structure to simplified progress schema
                completed = progress.get("completed_tasks", 0)
                total = progress.get("total_tasks", 0)
                summary_txt = f"{completed}/{total} tasks"
                overall = progress.get("overall_progress")
                # If no tasks but status completed, treat as fully done
                if total == 0 and progress.get("status") == "completed":
                    overall = 1.0
                started_at_iso = None
                completed_at_iso = None
                if adv_inv:
                    if getattr(adv_inv, "started_at", None):
                        started_at_iso = adv_inv.started_at.isoformat()
                    if getattr(adv_inv, "completed_at", None):
                        completed_at_iso = adv_inv.completed_at.isoformat()
                return {
                    "investigation_id": investigation_id,
                    "status": progress.get("status"),
                    "progress": overall,
                    "started_at": started_at_iso,
                    "completed_at": completed_at_iso,
                    "summary": summary_txt,
                }
            except Exception as e:  # pragma: no cover
                logger.error(f"Advanced progress fetch failed: {e}")
        # Fallback static behavior
        async with self._lock:
            inv2 = self._items.get(investigation_id)
            if not inv2:
                return {}
            progress_val = 0.0
            if inv2.status == SimpleStatus.running:
                progress_val = 0.25
            if inv2.status == SimpleStatus.completed:
                progress_val = 1.0
            return {
                "investigation_id": inv2.id,
                "status": inv2.status.value,
                "progress": progress_val,
                "started_at": inv2.started_at.isoformat() if inv2.started_at else None,
                "completed_at": (
                    inv2.completed_at.isoformat() if inv2.completed_at else None
                ),
                "summary": "Orchestration not yet integrated",
            }

    async def get_tasks(
        self,
        investigation_id: str,
        owner_id: str,
        skip: int = 0,
        limit: int = 100,
        status: Optional[str] = None,
        task_type: Optional[str] = None,
        include_meta: bool = False,
    ) -> Dict[str, Any]:
        """Return (optionally paginated / filtered) task list.

        Filters:
          status: filter by task.status.value
          task_type: filter by task.task_type
        Pagination via skip / limit. If include_meta, returns meta summary.
        """
        async with self._lock:
            inv = self._items.get(investigation_id)
            if not inv or inv.owner_id != owner_id:
                return {"investigation_id": investigation_id, "tasks": [], "total": 0}
            adv_id = inv.advanced_id
        if self.advanced_manager and adv_id:
            try:
                adv_inv = await self.advanced_manager.get_investigation(adv_id)
                if not adv_inv:
                    return {
                        "investigation_id": investigation_id,
                        "tasks": [],
                        "total": 0,
                    }
                rows = []
                for t_id, task in adv_inv.tasks.items():  # type: ignore[attr-defined]
                    try:
                        rows.append(
                            {
                                "id": t_id,
                                "name": task.name,
                                "type": task.task_type,
                                "status": task.status.value,
                                "progress": task.progress,
                                "targets": task.targets,
                                "priority": getattr(
                                    task.priority, "name", str(task.priority)
                                ),
                                "dependencies": task.dependencies,
                                "created_at": task.created_at.isoformat()
                                if task.created_at
                                else None,
                                "started_at": task.started_at.isoformat()
                                if task.started_at
                                else None,
                                "completed_at": task.completed_at.isoformat()
                                if task.completed_at
                                else None,
                                "estimated_duration": task.estimated_duration,
                                "actual_duration": task.actual_duration,
                                "retry_count": task.retry_count,
                                "max_retries": task.max_retries,
                                "error": task.error,
                            }
                        )
                    except Exception as inner_e:  # pragma: no cover
                        logger.error(f"Task serialization failed: {inner_e}")
                total = len(rows)
                # Apply filters
                if status:
                    rows = [r for r in rows if r["status"].lower() == status.lower()]
                if task_type:
                    rows = [r for r in rows if r["type"].lower() == task_type.lower()]
                filtered = len(rows)
                rows.sort(key=lambda r: (r.get("created_at") or ""), reverse=True)
                window = rows[skip : skip + limit]
                base = {
                    "investigation_id": investigation_id,
                    "tasks": window,
                    "total": filtered,
                }
                if include_meta:
                    base["meta"] = {
                        "total": total,
                        "filtered": filtered,
                        "skip": skip,
                        "limit": limit,
                    }
                return base
            except Exception as e:  # pragma: no cover
                logger.error(f"Advanced tasks fetch failed: {e}")
        # Fallback – no advanced manager
        empty = {"investigation_id": investigation_id, "tasks": [], "total": 0}
        if include_meta:
            empty["meta"] = {"total": 0, "filtered": 0, "skip": skip, "limit": limit}
        return empty

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    async def _ensure_default_tasks(self, inv: SimpleInvestigation):
        """Populate baseline tasks for an investigation if none exist.

        Strategy: Map investigation_type -> single primary enrichment task,
        plus a passive_search catch-all. Only run if there are currently zero tasks.
        """
        if not self.advanced_manager or not inv.advanced_id:
            return
        try:
            adv_inv = await self.advanced_manager.get_investigation(inv.advanced_id)
            if adv_inv and getattr(adv_inv, "tasks", {}):
                return  # already has tasks
            mapping = {
                "domain": "domain_recon",
                "ip": "ip_intelligence",
                "email": "email_intelligence",
                "company": "company_intelligence",
                "person": "passive_search",
            }
            primary = mapping.get(inv.investigation_type.lower())
            # Add primary task
            if primary:
                await self.advanced_manager.add_task(
                    inv.advanced_id,
                    name=f"Primary {primary}",
                    task_type=primary,
                    targets=inv.targets,
                )
            # Add passive_search if not already primary
            if primary != "passive_search":
                await self.advanced_manager.add_task(
                    inv.advanced_id,
                    name="Passive Surface Scan",
                    task_type="passive_search",
                    targets=inv.targets,
                )
        except Exception as e:  # pragma: no cover
            logger.error(f"Failed to seed default tasks: {e}")

    def resolve_simple_id(self, advanced_id: str) -> Optional[str]:
        return self._adv_index.get(advanced_id)

    # ------------------------------------------------------------------
    # Advanced manager bridging (future)
    # ------------------------------------------------------------------
    def attach_advanced_manager(self, manager: InvestigationManager):  # type: ignore
        self.advanced_manager = manager
        logger.info(
            "Advanced InvestigationManager attached (bridge pending integration)."
        )

    # ------------------------------------------------------------------
    # Soft delete / archive
    # ------------------------------------------------------------------
    async def archive(self, investigation_id: str, owner_id: str) -> bool:
        async with self._lock:
            inv = self._items.get(investigation_id)
            if not inv or inv.owner_id != owner_id:
                return False
            inv.archived = True
            if inv.status == SimpleStatus.running:
                inv.status = SimpleStatus.completed
        await self._flush()  # Moved outside lock
        return True

    # ------------------------------------------------------------------
    # Demo Helpers (no-advanced-manager synthetic tasks)
    # ------------------------------------------------------------------
    async def seed_demo_tasks(
        self, investigation_id: str, owner_id: str
    ) -> Dict[str, Any]:
        """Create synthetic tasks for demo when advanced manager is unavailable.

        Stores a lightweight tasks JSON alongside investigation file for UI demo.
        Idempotent: will not recreate if tasks file already exists.
        """
        async with self._lock:
            inv = self._items.get(investigation_id)
            if not inv or inv.owner_id != owner_id:
                raise ValueError("Investigation not found or unauthorized")
            if self.advanced_manager and inv.advanced_id:
                return {"message": "Advanced manager active - use real tasks"}
            # Instead of synthetic tasks now return planner plan (build or load)
            plan = self._load_or_build_plan(inv)
            # Normalize plan.tasks which may be a dict (id -> PlannedTask) or a list/iterable
            raw_tasks = getattr(plan, "tasks", {})
            if isinstance(raw_tasks, dict):
                iterable = raw_tasks.values()
            else:
                iterable = raw_tasks or []
            tasks_data = [
                {
                    "id": getattr(t, "id", None),
                    "name": self._cap_name(getattr(t, "capability_id", "")),
                    "type": getattr(t, "capability_id", ""),
                    "status": getattr(t, "status", "planned"),
                    "progress": 0,
                    "targets": inv.targets,
                    "priority": inv.priority,
                    "dependencies": getattr(t, "depends_on", []),
                    "created_at": inv.created_at.isoformat(),
                    "started_at": None,
                    "completed_at": None,
                    "estimated_duration": 30,
                    "actual_duration": None,
                    "retry_count": 0,
                    "max_retries": 0,
                    "error": None,
                }
                for t in iterable
            ]
            return {"seeded": True, "tasks": tasks_data}

    # ------------------------------------------------------------------
    # Plan persistence helpers
    # ------------------------------------------------------------------
    def _plan_file(self, investigation_id: str) -> Path:
        return self.storage_dir / f"{investigation_id}_plan.json"

    def _persist_plan(self, investigation_id: str, plan: Any):
        try:
            # Normalize tasks from Plan; plan.tasks may be a dict (id -> PlannedTask) or an iterable of PlannedTask
            tasks_list = []
            raw_tasks = getattr(plan, "tasks", {})
            if isinstance(raw_tasks, dict):
                iterable = raw_tasks.values()
            else:
                iterable = raw_tasks or []
            for t in iterable:
                tasks_list.append(
                    {
                        "id": getattr(t, "id", None),
                        "capability_id": getattr(t, "capability_id", None),
                        "inputs": getattr(t, "inputs", {}),
                        "depends_on": getattr(t, "depends_on", []),
                        "status": getattr(t, "status", "planned"),
                    }
                )
            data = {
                "investigation_id": getattr(plan, "investigation_id", investigation_id),
                "tasks": tasks_list,
            }
            pf = self._plan_file(investigation_id)
            pf.write_text(json.dumps(data, indent=2))
        except Exception as e:  # pragma: no cover
            logger.error(f"Failed to persist plan: {e}")

    def _load_or_build_plan(self, inv: SimpleInvestigation) -> Any:
        pf = self._plan_file(inv.id)
        if pf.exists():
            try:
                raw = json.loads(pf.read_text())
                tasks = {}
                from types import SimpleNamespace

                for t in raw.get("tasks", []):
                    # Construct a simple task-like object rather than calling the
                    # external PlannedTask constructor which may have a different signature.
                    tasks[t["id"]] = SimpleNamespace(
                        id=t["id"],
                        capability_id=t.get("capability_id"),
                        inputs=t.get("inputs", {}),
                        depends_on=t.get("depends_on", []),
                        status=t.get("status", "planned"),
                    )
                # Return a lightweight plan-like object exposing .investigation_id and .tasks
                return SimpleNamespace(investigation_id=inv.id, tasks=tasks)
            except Exception as e:  # pragma: no cover
                logger.error(f"Failed to load plan, rebuilding: {e}")
        planner = Planner()
        plan = None
        # Try a few possible builder names and call signatures to accommodate different Planner APIs.
        for builder_name in ("build_plan", "plan", "create_plan", "build"):
            builder = getattr(planner, builder_name, None)
            if callable(builder):
                try:
                    plan = builder(
                        investigation_id=inv.id,
                        investigation_type=inv.investigation_type,
                        targets=inv.targets,
                    )
                except TypeError:
                    try:
                        plan = builder(inv.id, inv.investigation_type, inv.targets)
                    except Exception:
                        plan = None
                except Exception:
                    plan = None
                if plan is not None:
                    break
        if plan is None:
            # Fallback to an empty plan representation if planner couldn't produce one.
            from types import SimpleNamespace

            plan = SimpleNamespace(investigation_id=inv.id, tasks={})
        # Ensure we return a normalized object with .tasks as a dict
        raw_tasks = getattr(plan, "tasks", None)
        if isinstance(raw_tasks, dict):
            norm_tasks = raw_tasks
        elif (
            raw_tasks is not None
            and hasattr(raw_tasks, "__iter__")
            and not isinstance(raw_tasks, dict)
        ):
            norm_tasks = {}
            for t in raw_tasks:
                if t is None:
                    continue
                tid = getattr(t, "id", None) or getattr(t, "name", None)
                if tid is None:
                    continue
                norm_tasks[tid] = t
        else:
            norm_tasks = {}
        from types import SimpleNamespace

        plan = SimpleNamespace(
            investigation_id=getattr(plan, "investigation_id", inv.id), tasks=norm_tasks
        )
        self._persist_plan(inv.id, plan)
        return plan

    def _cap_name(self, capability_id: str) -> str:
        try:
            from capabilities import REGISTRY

            cap = REGISTRY.get(capability_id)
            if cap:
                return cap.name
        except Exception:
            pass
        return capability_id
