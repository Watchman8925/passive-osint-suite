#!/usr/bin/env python3
"""
Investigation Adapter
Provides persistent storage interface for investigations.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, cast
from dataclasses import dataclass, asdict

from planner import Plan

logger = logging.getLogger(__name__)


@dataclass
class InvestigationItem:
    """Investigation data structure"""

    id: str
    advanced_id: Optional[str]
    name: str
    description: str
    targets: List[str]
    investigation_type: str
    priority: str
    tags: List[str]
    owner_id: str
    scheduled_start: Optional[str]
    auto_reporting: bool
    status: str
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    ai_analysis: Dict[str, Any]
    tasks: List[Dict[str, Any]]
    results: Dict[str, Any]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class PersistentInvestigationStore:
    """
    Persistent storage adapter for investigations using JSON file storage.
    """

    def __init__(self, storage_path: str = "./investigation_store"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        self.investigations_file = self.storage_path / "investigations.json"
        self.plans_dir = self.storage_path / "plans"
        self.plans_dir.mkdir(exist_ok=True)

        # In-memory cache
        self._items: Dict[str, InvestigationItem] = {}
        self._load_investigations()

    def _load_investigations(self):
        """Load investigations from JSON file"""
        if not self.investigations_file.exists():
            self._items = {}
            return

        try:
            with open(self.investigations_file, "r") as f:
                data = json.load(f)

            for item in data:
                inv_item = InvestigationItem(**item)
                self._items[inv_item.id] = inv_item

        except Exception as e:
            logger.error(f"Failed to load investigations: {e}")
            self._items = {}

    def _save_investigations(self):
        """Save investigations to JSON file"""
        try:
            data = [item.to_dict() for item in self._items.values()]
            with open(self.investigations_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save investigations: {e}")

    def get_investigation(self, investigation_id: str) -> Optional[InvestigationItem]:
        """Get investigation by ID"""
        return self._items.get(investigation_id)

    def save_investigation(self, investigation: InvestigationItem):
        """Save investigation"""
        self._items[investigation.id] = investigation
        self._save_investigations()

    def list_investigations(self) -> List[InvestigationItem]:
        """List all investigations"""
        return list(self._items.values())

    def _load_or_build_plan(self, investigation: InvestigationItem) -> Plan:
        """Load plan from file or build new one"""
        plan_file = self.plans_dir / f"{investigation.id}.json"

        if plan_file.exists():
            try:
                with open(plan_file, "r") as f:
                    plan_data = json.load(f)
                # Prefer Plan.from_dict if it exists, otherwise try constructing Plan directly.
                plan_from_dict = getattr(Plan, "from_dict", None)
                if callable(plan_from_dict):
                    # Ensure the returned object is treated as Plan for type checkers.
                    return cast(Plan, plan_from_dict(plan_data))
                try:
                    return Plan(**plan_data)
                except Exception:
                    # If neither method works, fall through to rebuild the plan below.
                    logger.debug(
                        f"Plan.from_dict not available and Plan(**data) failed for {investigation.id}; will rebuild"
                    )
            except Exception as e:
                logger.warning(f"Failed to load plan for {investigation.id}: {e}")

        # Build new plan if not found
        from planner import Planner

        planner = Planner()
        # Prefer a builder method if available on Planner (name may vary across versions)
        builder = getattr(planner, "build_plan", None)
        if not callable(builder):
            for alt in ("create_plan", "plan", "generate_plan", "build"):
                builder = getattr(planner, alt, None)
                if callable(builder):
                    break
        if callable(builder):
            return cast(
                Plan,
                builder(
                    investigation.id,
                    investigation.investigation_type,
                    investigation.targets,
                ),
            )
        # Fall back to constructing Plan directly using best-effort attempts
        try:
            return Plan(
                investigation.id,
                investigation.investigation_type,
                investigation.targets,
            )  # type: ignore
        except Exception:
            # Try a variety of keyword signatures that different Plan versions might accept.
            kwargs_variants = [
                {
                    "id": investigation.id,
                    "investigation_type": investigation.investigation_type,
                    "targets": investigation.targets,
                },
                {
                    "id": investigation.id,
                    "type": investigation.investigation_type,
                    "targets": investigation.targets,
                },
                {
                    "id": investigation.id,
                    "investigationType": investigation.investigation_type,
                    "targets": investigation.targets,
                },
                {
                    "id": investigation.id,
                    "name": investigation.name,
                    "targets": investigation.targets,
                },
                {
                    "uid": investigation.id,
                    "investigation_type": investigation.investigation_type,
                    "targets": investigation.targets,
                },
                {"id": investigation.id, "targets": investigation.targets},
            ]
            for kwargs in kwargs_variants:
                try:
                    return cast(Plan, Plan(**kwargs))  # type: ignore
                except Exception:
                    # Try the next variant if this one doesn't match the Plan signature.
                    continue
            try:
                return Plan()  # type: ignore
            except Exception as e:
                raise RuntimeError(f"Unable to build plan for {investigation.id}: {e}")

    def _persist_plan(self, investigation_id: str, plan: Plan):
        """Persist plan to file"""
        plan_file = self.plans_dir / f"{investigation_id}.json"
        try:
            # Prefer plan.to_dict() if available, else try plan.to_json(),
            # else try to use __dict__, dataclass.asdict, or finally str(plan).
            serializer = getattr(plan, "to_dict", None)
            if callable(serializer):
                serialized = serializer()
            else:
                serializer = getattr(plan, "to_json", None)
                if callable(serializer):
                    serialized = serializer()
                else:
                    try:
                        serialized = dict(plan.__dict__)  # type: ignore
                    except Exception:
                        try:
                            serialized = asdict(plan)  # type: ignore
                        except Exception:
                            serialized = str(plan)

            with open(plan_file, "w") as f:
                json.dump(serialized, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to persist plan for {investigation_id}: {e}")

    def update_investigation_status(self, investigation_id: str, status: str):
        """Update investigation status"""
        if investigation_id in self._items:
            self._items[investigation_id].status = status
            self._save_investigations()

    def add_task_result(self, investigation_id: str, task_id: str, result: Any):
        """Add task result to investigation"""
        if investigation_id in self._items:
            if "task_results" not in self._items[investigation_id].results:
                self._items[investigation_id].results["task_results"] = {}
            self._items[investigation_id].results["task_results"][task_id] = result
            self._save_investigations()
