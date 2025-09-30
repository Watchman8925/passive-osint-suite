"""
Investigation Planner
Creates and manages investigation plans
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class PlannedTask:
    """A planned investigation task"""

    id: str
    name: str
    description: str
    module: str
    parameters: Dict[str, Any]
    priority: int = 1
    dependencies: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


@dataclass
class Plan:
    """An investigation plan"""

    id: str
    name: str
    description: str
    tasks: List[PlannedTask]
    created_at: Optional[datetime] = None
    status: str = "draft"

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


class Planner:
    """Investigation planner"""

    def __init__(self):
        self.plans = {}

    def create_plan(self, investigation_id: str, objectives: List[str]) -> Plan:
        """Create an investigation plan"""
        tasks = []

        # Create tasks based on objectives
        for i, objective in enumerate(objectives):
            task = PlannedTask(
                id=f"task_{i}",
                name=f"Investigate {objective}",
                description=f"Investigate {objective}",
                module="passive_search",
                parameters={"query": objective},
                priority=1,
            )
            tasks.append(task)

        plan = Plan(
            id=investigation_id,
            name=f"Investigation Plan for {investigation_id}",
            description="Auto-generated investigation plan",
            tasks=tasks,
        )

        self.plans[investigation_id] = plan
        return plan

    def get_plan(self, plan_id: str) -> Optional[Plan]:
        """Get a plan by ID"""
        return self.plans.get(plan_id)

    def update_task_status(
        self, plan_id: str, task_id: str, status: TaskStatus
    ) -> bool:
        """Update task status"""
        plan = self.plans.get(plan_id)
        if not plan:
            return False

        for task in plan.tasks:
            if task.id == task_id:
                task.status = status
                if status == TaskStatus.COMPLETED:
                    task.completed_at = datetime.now()
                return True

        return False

    def get_next_task(self, plan_id: str) -> Optional[PlannedTask]:
        """Get the next pending task"""
        plan = self.plans.get(plan_id)
        if not plan:
            return None

        # Find pending tasks with satisfied dependencies
        for task in plan.tasks:
            if task.status == TaskStatus.PENDING:
                # Check if dependencies are satisfied
                deps_satisfied = all(
                    any(
                        t.id == dep and t.status == TaskStatus.COMPLETED
                        for t in plan.tasks
                    )
                    for dep in task.dependencies
                )
                if deps_satisfied:
                    return task

        return None
