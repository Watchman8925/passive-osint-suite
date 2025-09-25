# Real-Time WebSocket Events

This document describes the current WebSocket event model exposed by the OSINT Suite backend.

## Endpoint

`GET /ws/{client_id}` – Upgrade to a WebSocket connection.

## Subscribing

After connecting, send a JSON subscription message for each investigation you want updates for:

```json
{"type": "subscribe_investigation", "investigation_id": "<id>"}
```

Server confirms:
```json
{"type": "subscription_confirmed", "investigation_id": "<id>"}
```

## Event Envelope

All pushed updates currently use a wrapper:
```json
{
  "type": "investigation_update",
  "investigation_id": "<id>",
  "data": { /* event-specific payload */ }
}
```

### Event Payload (data)

Depending on lifecycle stage, `data` may include:

| Field | Description |
|-------|-------------|
| `type` | Event kind (e.g. `investigation_started`, `investigation_completed`, `task_started`, `task_completed`, `task_failed`) |
| `status` | Investigation or task status (string) |
| `message` | Human-readable status message |
| `investigation_id` | Mirrors outer id (added for convenience) |
| `task_id` | Present for task events |
| `name` | Task name (task events) |
| `progress` | Float 0..1 for task progress |

### Example: Investigation Started
```json
{
  "type": "investigation_update",
  "investigation_id": "1234",
  "data": {
    "type": "investigation_started",
    "status": "running",
    "message": "Investigation started",
    "investigation_id": "1234"
  }
}
```

### Example: Task Completed
```json
{
  "type": "investigation_update",
  "investigation_id": "1234",
  "data": {
    "type": "task_completed",
    "task_id": "abcd",
    "name": "Primary domain_recon",
    "status": "completed",
    "progress": 1.0,
    "investigation_id": "1234"
  }
}
```

## Guaranteed vs. Best-Effort

| Aspect | Status |
|--------|--------|
| Delivery ordering per investigation | Best effort (generally FIFO) |
| Reconnection / replay | Not implemented yet |
| Heartbeats | Not implemented (future) |
| Broadcast fallback (no subscription) | Currently falls back to all connections |

## Client Recommendations
1. Always subscribe explicitly after connecting (future versions may remove fallback broadcast).
2. Handle unknown fields gracefully; schema may expand.
3. Treat missing `data.type` with `status=running` + startup message as `investigation_started` (legacy compatibility).
4. Implement idle timeout handling; consider ping/pong in client for resilience.

## Roadmap Enhancements
- Explicit ping/pong heartbeats
- Optional compressed event stream
- Replay token for missed events after reconnect
- Fine-grained subscription scopes (tasks only, summary only)
- Rate limiting & backpressure signalling

---
Last updated: Automated addition during real-time feature hardening phase.