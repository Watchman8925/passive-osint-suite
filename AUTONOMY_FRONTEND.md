# Autonomy Frontend Guide

This document explains the lifecycle of the autonomous investigation features exposed in the web UI: capabilities catalog → plan generation → task execution → evidence provenance verification.

## 1. Capabilities Catalog
Endpoint: `GET /api/capabilities`
UI: `Capabilities` tab in Investigation modal.
Each capability has: id, category, risk_level, cost_weight, produces (entity/relationship types), dependencies.
Use this to understand what building blocks are available to the planner.

## 2. Plan Generation
Endpoint: `GET /api/investigations/{id}/plan`
Behavior: If a plan has not yet been built, the backend lazily constructs a dependency-resolved DAG of tasks (one per capability selected/relevant). Frontend exposes a "Generate Plan" button in the Plan tab when no plan exists.
Returned Shape: `{ investigation_id, tasks: PlannedTask[] }` where each task has id, capability_id, depends_on, status (pending|running|completed|failed).

## 3. Task Execution
Endpoints:
- `POST /api/investigations/{id}/execute/next` – executes the next eligible task (internal ordering uses risk level + cost heuristics + dependency satisfaction).
- `POST /api/investigations/{id}/execute/all` – sequentially executes every remaining task.
Live Updates: WebSocket `/api/ws` sends events (currently multiplexed via `investigation_update`) with fields: `event` (task_started|task_completed|task_failed), `task_id`, `capability_id`, `status`.
Frontend merges these into local plan state via `usePlan` + `useInvestigationWebSocket`.

Execution UX:
- Run Next / Run All buttons disabled while an execution request is in flight.
- Spinner indicators and next-runnable hint show which tasks are ready (no unmet dependencies).
- Toasts appear for task completion or failure.

## 4. Evidence & Provenance
Endpoint: `GET /api/investigations/{id}/evidence/provenance`
Provides: Merkle root, leaves (hashes of evidence records). After executing tasks, refresh the Provenance tab to verify an integrity root exists. Any tampering of stored evidence would invalidate recomputed root.

## 5. WebSocket Integration
Subscribe: Client sends `{ type: 'subscribe', investigation_id }` over `/api/ws` upon opening the modal.
Events parsed in `useWebSocket` and task statuses updated in-memory.
If connection drops, auto-reconnect logic attempts limited retries.

## 6. Component Overview
- `CapabilityCatalog`: Lists capabilities with risk & cost color badges.
- `PlanViewer`: Shows tasks, controls execution, plan generation guard state, next runnable hint, cancellation placeholder.
- `ProvenancePanel`: Displays current Merkle root and expandable list of leaf hashes.

## 7. Hooks
- `useCapabilities()`: Fetch capabilities list.
- `usePlan(investigationId)`: Fetches plan and merges live task status updates.
- `useExecution(investigationId)`: Exposes `runNext`, `runAll`, execution state, last result.
- `useProvenance(investigationId)`: Fetch provenance summary.

## 8. Failure Handling
- WebSocket task_failed events trigger toast error messages.
- Fetch / execution promise rejections surface inline error text in components.
- Future enhancement: central error boundary + retry logic.

## 9. Testing Strategy (initial)
Current placeholder Vitest tests assert structural rendering and hook shape. Recommended improvements:
- Mock WebSocket with a virtual emitter to simulate task lifecycle transitions and assert merged plan status order.
- Mock API client to return deterministic plan & provenance payloads.

## 10. Future Enhancements
- Parallel execution / concurrency controls.
- Task cancellation & retry semantics (UI placeholder already present).
- Entity & relationship visualization, counts surfaced in plan/provenance views.
- Offline caching & optimistic plan updates.
- Stronger event schema versioning over WebSocket (dedicated channel for execution events).

## 11. Developer Notes
If adding new capabilities:
1. Implement backend capability module (produces entities/evidence).
2. Register capability in capability registry.
3. Ensure planner includes new capability where relevant (dependency mapping).
4. No frontend changes required unless new metadata fields should be visualized.

---
This guide will evolve alongside autonomy features; keep it updated when adding new execution controls or provenance verification affordances.
