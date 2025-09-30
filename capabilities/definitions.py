from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

# Lightweight domain enums (could become Enum classes later)
CapabilityCategory = str  # e.g., 'dns', 'infra', 'whois', 'ssl'
RiskLevel = str  # e.g., 'low', 'medium', 'high'


@dataclass(frozen=True)
class CapabilityDefinition:
    """Declarative metadata for a capability.

    execute callable signature: execute(context: dict, **inputs) -> CapabilityResult
    (context may later include investigation_id, transport/session handles, graph adapter, etc.)
    """

    id: str
    name: str
    description: str
    category: CapabilityCategory
    version: str
    inputs: Dict[str, str]  # simple schema: name -> description
    produces: Sequence[str]  # entity types or artifact labels
    dependencies: Sequence[str] = field(default_factory=tuple)
    cost_weight: float = 1.0
    risk_level: RiskLevel = "low"
    enabled: bool = True
    execute: Optional[Callable[..., "CapabilityResult"]] = None


@dataclass
class CapabilityResult:
    capability_id: str
    started_at: float
    completed_at: float
    success: bool
    error: Optional[str]
    produced_entities: List[Dict[str, Any]]
    produced_relationships: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]  # references (not raw blobs)
    metrics: Dict[str, Any]

    @classmethod
    def start(cls, capability_id: str) -> "CapabilityResult":
        now = time.time()
        return cls(
            capability_id=capability_id,
            started_at=now,
            completed_at=now,
            success=False,
            error=None,
            produced_entities=[],
            produced_relationships=[],
            evidence=[],
            metrics={},
        )

    def mark_complete(self, success: bool, error: Optional[str] = None):
        self.completed_at = time.time()
        self.success = success
        self.error = error
        return self
