#!/usr/bin/env python3
"""
OSINT Investigation Manager
Advanced workflow orchestration and data organization for complex OSINT investigations.
"""

import asyncio
import json
import logging
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import aiofiles
from result_encryption import ResultEncryption

from audit_trail import AuditTrail
# Import existing OSINT modules
from osint_suite import OSINTSuite

try:
    from query_obfuscation import \
        QueryObfuscator as QueryObfuscation  # backward alias
except Exception:  # pragma: no cover
    QueryObfuscation = None  # type: ignore
# (Removed unused AnonymityGrid import to reduce unnecessary dependencies)
from secrets_manager import SecretsManager

logger = logging.getLogger(__name__)


class InvestigationStatus(Enum):
    """Investigation status enumeration"""
    CREATED = "created"
    PLANNING = "planning"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ARCHIVED = "archived"


class TaskStatus(Enum):
    """Task status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRY = "retry"


class Priority(Enum):
    """Task priority enumeration"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class InvestigationTask:
    """Individual investigation task"""
    id: str
    # Parent investigation identifier (added for WebSocket/event correlation)
    parent_id: str
    name: str
    task_type: str
    targets: List[str]
    parameters: Dict[str, Any]
    status: TaskStatus
    priority: Priority
    dependencies: List[str]
    estimated_duration: int
    actual_duration: Optional[int]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    result: Optional[Dict[str, Any]]
    error: Optional[str]
    retry_count: int
    max_retries: int
    progress: float
    metadata: Dict[str, Any]


@dataclass
class Investigation:
    """Complete investigation structure"""
    id: str
    name: str
    description: str
    investigation_type: str
    status: InvestigationStatus
    priority: Priority
    targets: List[str]
    tags: List[str]
    analyst: str
    organization: str
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    deadline: Optional[datetime]
    estimated_duration: int
    tasks: Dict[str, InvestigationTask]
    dependencies: Dict[str, List[str]]
    results: Dict[str, Any]
    ai_analysis: Optional[Dict[str, Any]]
    configuration: Dict[str, Any]
    metadata: Dict[str, Any]


class InvestigationManager:
    """
    Advanced investigation manager for orchestrating complex OSINT workflows.
    Handles scheduling, dependency management, progress tracking, and
    result aggregation.
    """
    
    def __init__(
        self,
        osint_suite: OSINTSuite,
        audit_trail: AuditTrail,
        result_encryption: ResultEncryption,
        secrets_manager: SecretsManager,
        storage_path: str = "./investigations"
    ):
        self.osint_suite = osint_suite
        self.audit_trail = audit_trail
        self.result_encryption = result_encryption
        self.secrets_manager = secrets_manager
        self.storage_path = Path(storage_path)
        
        # Active investigations
        self.investigations: Dict[str, Investigation] = {}
        
        # Task execution pool
        self.max_concurrent_tasks = 10
        self.task_semaphore = asyncio.Semaphore(self.max_concurrent_tasks)
        
        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = {
            "investigation_created": [],
            "investigation_started": [],
            "investigation_completed": [],
            "task_started": [],
            "task_completed": [],
            "task_failed": [],
            "progress_updated": []
        }
        
        # Initialize storage
        self._init_storage()
    
    def _init_storage(self):
        """Initialize investigation storage"""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        (self.storage_path / "active").mkdir(exist_ok=True)
        (self.storage_path / "completed").mkdir(exist_ok=True)
        (self.storage_path / "archived").mkdir(exist_ok=True)
    
    async def create_investigation(
        self,
        name: str,
        description: str,
        investigation_type: str,
        targets: List[str],
        analyst: str = "AI Assistant",
        organization: str = "OSINT Investigation",
        priority: Priority = Priority.MEDIUM,
        deadline: Optional[datetime] = None,
        tags: List[str] = None,
        configuration: Dict[str, Any] = None
    ) -> str:
        """
        Create a new investigation.
        
        Args:
            name: Investigation name
            description: Detailed description
            investigation_type: Type of investigation (domain, person, company, etc.)
            targets: List of investigation targets
            analyst: Analyst name
            organization: Organization name
            priority: Investigation priority
            deadline: Optional deadline
            tags: Optional tags for categorization
            configuration: Investigation-specific configuration
        
        Returns:
            Investigation ID
        """
        investigation_id = str(uuid.uuid4())
        
        investigation = Investigation(
            id=investigation_id,
            name=name,
            description=description,
            investigation_type=investigation_type,
            status=InvestigationStatus.CREATED,
            priority=priority,
            targets=targets,
            tags=tags or [],
            analyst=analyst,
            organization=organization,
            created_at=datetime.now(),
            started_at=None,
            completed_at=None,
            deadline=deadline,
            estimated_duration=0,
            tasks={},
            dependencies={},
            results={},
            ai_analysis=None,
            configuration=configuration or {},
            metadata={}
        )
        
        # Store investigation
        self.investigations[investigation_id] = investigation
        await self._save_investigation(investigation)
        
        # Log creation
        await self.audit_trail.log_action(
            action="investigation_created",
            details={
                "investigation_id": investigation_id,
                "name": name,
                "type": investigation_type,
                "targets": targets
            }
        )
        
        # Trigger event handlers
        await self._trigger_event("investigation_created", investigation)
        
        return investigation_id
    
    async def add_task(
        self,
        investigation_id: str,
        name: str,
        task_type: str,
        targets: List[str],
        parameters: Dict[str, Any] = None,
        priority: Priority = Priority.MEDIUM,
        dependencies: List[str] = None,
        estimated_duration: int = 300,  # 5 minutes default
        max_retries: int = 3
    ) -> str:
        """Add a task to an investigation"""
        if investigation_id not in self.investigations:
            raise ValueError(f"Investigation {investigation_id} not found")
        
        task_id = str(uuid.uuid4())
        
        task = InvestigationTask(
            id=task_id,
            parent_id=investigation_id,
            name=name,
            task_type=task_type,
            targets=targets,
            parameters=parameters or {},
            status=TaskStatus.PENDING,
            priority=priority,
            dependencies=dependencies or [],
            estimated_duration=estimated_duration,
            actual_duration=None,
            created_at=datetime.now(),
            started_at=None,
            completed_at=None,
            result=None,
            error=None,
            retry_count=0,
            max_retries=max_retries,
            progress=0.0,
            metadata={}
        )
        
        # Add task to investigation
        investigation = self.investigations[investigation_id]
        investigation.tasks[task_id] = task
        investigation.estimated_duration += estimated_duration
        
        # Update dependency graph
        if task_id not in investigation.dependencies:
            investigation.dependencies[task_id] = dependencies or []
        
        await self._save_investigation(investigation)
        
        logger.info(f"Added task {task_id} to investigation {investigation_id}")
        return task_id
    
    async def start_investigation(self, investigation_id: str) -> bool:
        """Start an investigation"""
        if investigation_id not in self.investigations:
            raise ValueError(f"Investigation {investigation_id} not found")
        
        investigation = self.investigations[investigation_id]
        
        if investigation.status != InvestigationStatus.CREATED:
            raise ValueError(
                f"Investigation {investigation_id} is not in created state"
            )
        
        # Update status
        investigation.status = InvestigationStatus.ACTIVE
        investigation.started_at = datetime.now()
        
        await self._save_investigation(investigation)
        
        # Log start
        await self.audit_trail.log_action(
            action="investigation_started",
            details={
                "investigation_id": investigation_id,
                "name": investigation.name,
                "task_count": len(investigation.tasks)
            }
        )
        
        # Trigger event handlers
        await self._trigger_event("investigation_started", investigation)
        
        # Start task execution
        asyncio.create_task(self._execute_investigation(investigation_id))
        
        return True
    
    async def _execute_investigation(self, investigation_id: str):
        """Execute investigation tasks"""
        try:
            investigation = self.investigations[investigation_id]
            
            # Build execution plan
            execution_plan = self._build_execution_plan(investigation)
            
            # Execute tasks in planned order
            for task_batch in execution_plan:
                # Execute tasks in batch (parallel execution for independent tasks)
                batch_tasks = []
                for task_id in task_batch:
                    batch_tasks.append(self._execute_task(investigation_id, task_id))
                
                # Wait for batch completion
                await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            # Complete investigation
            await self._complete_investigation(investigation_id)
            
        except Exception as e:
            logger.error(f"Investigation execution failed: {e}")
            await self._fail_investigation(investigation_id, str(e))
    
    def _build_execution_plan(self, investigation: Investigation) -> List[List[str]]:
        """Build task execution plan based on dependencies"""
        # Topological sort with batching for parallel execution
        executed = set()
        execution_plan = []
        
        while len(executed) < len(investigation.tasks):
            current_batch = []
            
            for task_id, task in investigation.tasks.items():
                if task_id in executed:
                    continue
                
                # Check if all dependencies are satisfied
                dependencies_met = all(
                    dep_id in executed 
                    for dep_id in investigation.dependencies.get(task_id, [])
                )
                
                if dependencies_met:
                    current_batch.append(task_id)
            
            if not current_batch:
                # Circular dependency or other issue
                remaining_tasks = [
                    task_id for task_id in investigation.tasks.keys() 
                    if task_id not in executed
                ]
                logger.warning(
                    f"Dependency deadlock detected for tasks: {remaining_tasks}"
                )
                current_batch = remaining_tasks  # Execute remaining tasks anyway
            
            execution_plan.append(current_batch)
            executed.update(current_batch)
        
        return execution_plan
    
    async def _execute_task(self, investigation_id: str, task_id: str):
        """Execute a single investigation task"""
        async with self.task_semaphore:
            investigation = self.investigations[investigation_id]
            task = investigation.tasks[task_id]
            
            try:
                # Update task status
                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now()
                task.progress = 0.1
                
                await self._save_investigation(investigation)
                await self._trigger_event("task_started", task)
                
                # Execute task based on type
                result = await self._dispatch_task(task)
                
                # Update task with result
                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now()
                task.actual_duration = int(
                    (task.completed_at - task.started_at).total_seconds()
                )
                task.result = result
                task.progress = 1.0
                
                # Store result in investigation
                investigation.results[task_id] = result
                
                await self._save_investigation(investigation)
                await self._trigger_event("task_completed", task)
                
                logger.info(f"Task {task_id} completed successfully")
                
            except Exception as e:
                # Handle task failure
                task.status = TaskStatus.FAILED
                task.error = str(e)
                task.retry_count += 1
                
                await self._save_investigation(investigation)
                await self._trigger_event("task_failed", task)
                
                logger.error(f"Task {task_id} failed: {e}")
                
                # Retry logic
                if task.retry_count < task.max_retries:
                    logger.info(
                        f"Retrying task {task_id} (attempt {task.retry_count + 1})"
                    )
                    task.status = TaskStatus.RETRY
                    await asyncio.sleep(2 ** task.retry_count)  # Exponential backoff
                    await self._execute_task(investigation_id, task_id)
    
    async def _dispatch_task(self, task: InvestigationTask) -> Dict[str, Any]:
        """Dispatch task to appropriate OSINT module"""
        task_type = task.task_type.lower()
        targets = task.targets
        parameters = task.parameters
        
        # Update progress
        task.progress = 0.2
        
        if task_type == "domain_recon":
            from domain_recon import DomainRecon
            domain_recon = DomainRecon(self.secrets_manager)
            result = {}
            for target in targets:
                target_result = await domain_recon.comprehensive_domain_analysis(
                    target, **parameters
                )
                result[target] = target_result
                task.progress = min(0.9, task.progress + (0.7 / len(targets)))
            
        elif task_type == "ip_intelligence":
            from ip_intel import IPIntel
            ip_intel = IPIntel(self.secrets_manager)
            result = {}
            for target in targets:
                target_result = await ip_intel.comprehensive_ip_analysis(
                    target, **parameters
                )
                result[target] = target_result
                task.progress = min(0.9, task.progress + (0.7 / len(targets)))
        
        elif task_type == "email_intelligence":
            from email_intel import EmailIntel
            email_intel = EmailIntel(self.secrets_manager)
            result = {}
            for target in targets:
                target_result = await email_intel.comprehensive_email_analysis(
                    target, **parameters
                )
                result[target] = target_result
                task.progress = min(0.9, task.progress + (0.7 / len(targets)))
        
        elif task_type == "company_intelligence":
            from company_intel import CompanyIntel
            company_intel = CompanyIntel(self.secrets_manager)
            result = {}
            for target in targets:
                target_result = await company_intel.comprehensive_company_analysis(
                    target, **parameters
                )
                result[target] = target_result
                task.progress = min(0.9, task.progress + (0.7 / len(targets)))
        
        elif task_type == "flight_intelligence":
            from flight_intel import FlightIntel
            flight_intel = FlightIntel(self.secrets_manager)
            result = {}
            for target in targets:
                target_result = await flight_intel.comprehensive_flight_analysis(
                    target, **parameters
                )
                result[target] = target_result
                task.progress = min(0.9, task.progress + (0.7 / len(targets)))
        
        elif task_type == "crypto_intelligence":
            from crypto_intel import CryptoIntel
            crypto_intel = CryptoIntel(self.secrets_manager)
            result = {}
            for target in targets:
                target_result = await crypto_intel.comprehensive_crypto_analysis(
                    target, **parameters
                )
                result[target] = target_result
                task.progress = min(0.9, task.progress + (0.7 / len(targets)))
        
        elif task_type == "passive_search":
            from passive_search import PassiveSearch
            passive_search = PassiveSearch(self.secrets_manager)
            result = await passive_search.comprehensive_passive_search(
                targets, **parameters
            )
        
        else:
            raise ValueError(f"Unknown task type: {task_type}")
        
        # Final progress update
        task.progress = 1.0
        
        return {
            "status": "completed",
            "data": result,
            "metadata": {
                "task_type": task_type,
                "targets": targets,
                "execution_time": task.actual_duration,
                "timestamp": datetime.now().isoformat()
            }
        }
    
    async def _complete_investigation(self, investigation_id: str):
        """Mark investigation as completed"""
        investigation = self.investigations[investigation_id]
        
        investigation.status = InvestigationStatus.COMPLETED
        investigation.completed_at = datetime.now()
        
        await self._save_investigation(investigation)
        
        # Log completion
        await self.audit_trail.log_action(
            action="investigation_completed",
            details={
                "investigation_id": investigation_id,
                "name": investigation.name,
                "duration": (
                    (investigation.completed_at - investigation.started_at)
                    .total_seconds()
                ),
                "task_count": len(investigation.tasks)
            }
        )
        
        # Trigger event handlers
        await self._trigger_event("investigation_completed", investigation)
        
        # Archive investigation
        await self._archive_investigation(investigation_id)
    
    async def _fail_investigation(self, investigation_id: str, error: str):
        """Mark investigation as failed"""
        investigation = self.investigations[investigation_id]
        
        investigation.status = InvestigationStatus.FAILED
        investigation.metadata["error"] = error
        
        await self._save_investigation(investigation)
        
        logger.error(f"Investigation {investigation_id} failed: {error}")
    
    async def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        """Get investigation by ID"""
        if investigation_id in self.investigations:
            return self.investigations[investigation_id]
        
        # Try to load from storage
        return await self._load_investigation(investigation_id)
    
    async def list_investigations(
        self,
        status: Optional[InvestigationStatus] = None,
        analyst: Optional[str] = None,
        investigation_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Investigation]:
        """List investigations with optional filtering"""
        investigations = list(self.investigations.values())
        
        # Apply filters
        if status:
            investigations = [i for i in investigations if i.status == status]
        if analyst:
            investigations = [i for i in investigations if i.analyst == analyst]
        if investigation_type:
            investigations = [
                i for i in investigations
                if i.investigation_type == investigation_type
            ]
        
        # Sort by creation date (newest first)
        investigations.sort(key=lambda x: x.created_at, reverse=True)
        
        return investigations[:limit]
    
    async def pause_investigation(self, investigation_id: str) -> bool:
        """Pause an active investigation"""
        if investigation_id not in self.investigations:
            return False
        
        investigation = self.investigations[investigation_id]
        
        if investigation.status != InvestigationStatus.ACTIVE:
            return False
        
        investigation.status = InvestigationStatus.PAUSED
        await self._save_investigation(investigation)
        
        return True
    
    async def resume_investigation(self, investigation_id: str) -> bool:
        """Resume a paused investigation"""
        if investigation_id not in self.investigations:
            return False
        
        investigation = self.investigations[investigation_id]
        
        if investigation.status != InvestigationStatus.PAUSED:
            return False
        
        investigation.status = InvestigationStatus.ACTIVE
        await self._save_investigation(investigation)
        
        # Resume task execution
        asyncio.create_task(self._execute_investigation(investigation_id))
        
        return True
    
    async def get_investigation_progress(self, investigation_id: str) -> Dict[str, Any]:
        """Get investigation progress information"""
        investigation = await self.get_investigation(investigation_id)
        
        if not investigation:
            return {}
        
        total_tasks = len(investigation.tasks)
        completed_tasks = sum(
            1 for task in investigation.tasks.values() 
            if task.status == TaskStatus.COMPLETED
        )
        failed_tasks = sum(
            1 for task in investigation.tasks.values() 
            if task.status == TaskStatus.FAILED
        )
        running_tasks = sum(
            1 for task in investigation.tasks.values() 
            if task.status == TaskStatus.RUNNING
        )
        
        overall_progress = 0.0
        if total_tasks > 0:
            overall_progress = sum(
                task.progress for task in investigation.tasks.values()
            ) / total_tasks
        
        estimated_completion = None
        if investigation.started_at and overall_progress > 0:
            elapsed = datetime.now() - investigation.started_at
            total_estimated = elapsed / overall_progress
            estimated_completion = investigation.started_at + total_estimated
        
        return {
            "investigation_id": investigation_id,
            "status": investigation.status.value,
            "overall_progress": overall_progress,
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "running_tasks": running_tasks,
            "estimated_completion": (
                estimated_completion.isoformat()
                if estimated_completion else None
            ),
            "task_progress": {
                task_id: {
                    "name": task.name,
                    "status": task.status.value,
                    "progress": task.progress
                }
                for task_id, task in investigation.tasks.items()
            }
        }
    
    async def _save_investigation(self, investigation: Investigation):
        """Save investigation to storage"""
        file_path = self.storage_path / "active" / f"{investigation.id}.json"
        
        # Convert investigation to dict
        investigation_dict = asdict(investigation)
        
        # Convert datetime objects to ISO format
        investigation_dict = self._serialize_datetime(investigation_dict)

        # Sanitize any non-JSON-serializable primitives (enums, mappingproxy, sets, etc.)
        def _sanitize(obj):  # type: ignore
            if isinstance(obj, Enum):
                return obj.value
            from types import MappingProxyType
            if isinstance(obj, MappingProxyType):  # convert to plain dict
                return {k: _sanitize(v) for k, v in obj.items()}
            if isinstance(obj, dict):
                return {k: _sanitize(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_sanitize(v) for v in obj]
            if isinstance(obj, set):
                return [_sanitize(v) for v in obj]
            return obj
        investigation_dict = _sanitize(investigation_dict)
        
        async with aiofiles.open(file_path, 'w') as f:
            await f.write(json.dumps(investigation_dict, indent=2))
    
    async def _load_investigation(self, investigation_id: str) -> Optional[Investigation]:
        """Load investigation from storage"""
        file_path = self.storage_path / "active" / f"{investigation_id}.json"
        
        if not file_path.exists():
            return None
        
        try:
            async with aiofiles.open(file_path, 'r') as f:
                data = await f.read()
            
            investigation_dict = json.loads(data)
            investigation_dict = self._deserialize_datetime(investigation_dict)
            
            # Convert back to Investigation object
            investigation = Investigation(**investigation_dict)
            
            # Convert tasks back to InvestigationTask objects
            tasks = {}
            for task_id, task_data in investigation_dict["tasks"].items():
                # Backward compatibility: older tasks may not have parent_id
                if "parent_id" not in task_data:
                    task_data["parent_id"] = investigation_id
                tasks[task_id] = InvestigationTask(**task_data)
            investigation.tasks = tasks
            
            self.investigations[investigation_id] = investigation
            return investigation
            
        except Exception as e:
            logger.error(f"Failed to load investigation {investigation_id}: {e}")
            return None
    
    async def _archive_investigation(self, investigation_id: str):
        """Archive completed investigation"""
        source_path = self.storage_path / "active" / f"{investigation_id}.json"
        dest_path = self.storage_path / "completed" / f"{investigation_id}.json"
        
        if source_path.exists():
            source_path.rename(dest_path)
    
    def _serialize_datetime(self, obj: Any) -> Any:
        """Recursively serialize datetime objects to ISO format"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: self._serialize_datetime(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_datetime(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            return self._serialize_datetime(obj.__dict__)
        else:
            return obj
    
    def _deserialize_datetime(self, obj: Any) -> Any:
        """Recursively deserialize ISO format strings to datetime objects"""
        if isinstance(obj, str):
            try:
                return datetime.fromisoformat(obj)
            except ValueError:
                return obj
        elif isinstance(obj, dict):
            return {k: self._deserialize_datetime(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deserialize_datetime(item) for item in obj]
        else:
            return obj
    
    async def _trigger_event(self, event_name: str, data: Any):
        """Trigger event handlers"""
        handlers = self.event_handlers.get(event_name, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as e:
                logger.error(f"Event handler failed for {event_name}: {e}")
    
    def add_event_handler(self, event_name: str, handler: Callable):
        """Add event handler"""
        if event_name not in self.event_handlers:
            self.event_handlers[event_name] = []
        self.event_handlers[event_name].append(handler)
    
    def remove_event_handler(self, event_name: str, handler: Callable):
        """Remove event handler"""
        if event_name in self.event_handlers:
            try:
                self.event_handlers[event_name].remove(handler)
            except ValueError:
                pass