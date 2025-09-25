# OSINT Suite Deployment Guide

This guide covers running the OSINT Suite in development and production containers, environment configuration, security notes, and scaling considerations.

## 1. Quick Start (Development)

```bash
# Run backend + dependencies (no frontend build step yet)
docker compose up -d --build osint-suite tor-proxy redis postgres

# Check health
curl http://localhost:8000/health
curl http://localhost:8000/api/health
```

Generate a dev JWT (only if `ENABLE_DEV_AUTH=1` set):
```bash
curl -X POST 'http://localhost:8000/api/dev/token?sub=dev-user&expires_minutes=120'
```

Use the `token` value as `Authorization: Bearer <token>` for secured endpoints.

## 2. Services Overview

| Service        | Port | Purpose                             |
|----------------|------|-------------------------------------|
| osint-suite    | 8000 | FastAPI backend (investigations, AI)|
| tor-proxy      | 9050 | Tor SOCKS proxy                     |
| tor-proxy ctl  | 9051 | Tor control port                    |
| redis          | 6379 | Caching / future rate limit store   |
| postgres       | 5432 | (Internal) Audit trail DB           |
| prometheus     | 9090 | Metrics (optional)                  |
| loki           | 3100 | Logs aggregation (optional)         |
| grafana        | 3000 | Dashboards (optional)               |

## 3. Building the Frontend

Frontend (React/Vite) currently runs via development tooling. To containerize:

```bash
cd web
npm ci
npm run build
# Outputs to dist/
```

Then enable the `web` service in `docker-compose.yml` (uncomment) and ensure the volume `./web/dist:/usr/share/nginx/html:ro` is present.

## 4. Environment Variables

| Variable             | Description                                   | Default / Notes |
|---------------------|-----------------------------------------------|-----------------|
| OSINT_MASTER_KEY     | Master key for secrets encryption             | (required prod) |
| OSINT_USE_KEYRING    | Enable keyring backend                        | false in containers |
| OSINT_TEST_MODE      | Relaxed behaviors for demos/tests             | false |
| ENABLE_DEV_AUTH      | Allow /api/dev/token issuance                 | unset (disabled) |
| TOR_CONTROL_PORT     | Tor control port                              | 9051 |
| TOR_SOCKS_PORT       | Tor SOCKS port                                | 9050 |
| REDIS_URL            | Redis connection string                       | redis://redis:6379 |
| DATABASE_URL         | Future relational DB connection               | (unused placeholder) |

Set production secrets via a `.env` file or orchestrator secrets manager:
```bash
OSINT_MASTER_KEY=change_me_strong_value
ENABLE_DEV_AUTH=0
```

## 5. Rate Limiting

A naive in-memory rate limiter now protects critical write endpoints:

| Endpoint                               | Limit               |
|----------------------------------------|---------------------|
| POST /api/investigations               | 15 per 60s          |
| POST /api/investigations/{id}/start    | 30 per 5m           |
| POST /api/ai/analyze                   | 10 per 5m           |
| POST /api/reports/generate             | 5 per 5m            |

For production, migrate to Redis-based sliding window or token bucket. Example strategy:
- Key: `rl:{user_id}:{route}`
- Maintain sorted timestamps ZSET; prune < now-window.
- Evaluate cardinality before adding.

## 6. WebSocket Integration

Current server endpoint: `/ws/{client_id}`. Clients must send a JSON message:
```json
{ "type": "subscribe_investigation", "investigation_id": "abc123" }
```
Then updates are broadcast with envelopes like:
```json
{
  "type": "investigation_update",
  "investigation_id": "abc123",
  "data": { "status": "running", "progress": 42.5 }
}
```

Task-level events from the advanced manager are normalized into the same broadcast channel.

## 7. Production Hardening Checklist

- [ ] Replace in-memory rate limiter with Redis-backed implementation
- [ ] Configure HTTPS (reverse proxy: Nginx / Traefik / Caddy)
- [ ] Rotate `SECRET_KEY` and `OSINT_MASTER_KEY` via secrets manager
- [ ] Enable structured logging (JSON) + ship to Loki/ELK
- [ ] Enable OpenTelemetry (traces / metrics) (future)
- [ ] Enforce stricter CORS (`AppConfig.CORS_ORIGINS`)
- [ ] Add JWT refresh / revocation logic
- [ ] Implement RBAC / scopes enforcement per endpoint
- [ ] Add SAST/Dependency scanning in CI pipeline
- [ ] Back up `output/` (encrypted results) securely

## 8. Scaling Considerations

| Concern           | Current | Scaling Path |
|-------------------|---------|--------------|
| Rate limiting     | Memory  | Redis / API Gateway |
| Task execution    | Single process | Worker queue (Celery/RQ/FastStream) |
| WebSocket fanout  | In-process | Redis pub/sub or NATS |
| Persistence       | JSON store | Postgres + ORM + migrations |
| Search/Analytics  | Elastic placeholder | Real Elasticsearch / OpenSearch |

## 9. Local Development Tips

```bash
# Run only backend fast path (no external services needed)
python api/api_server.py

# Run tests
pytest -q

# Smoke test (health + tor)
python tests/smoke_health.py
```

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| 429 errors quickly | Rate limit thresholds hit | Tune limits or inspect abusive client |
| WebSocket not receiving updates | Missing subscription message | Send subscribe JSON after connect |
| Tor status shows unreachable | No tor-proxy container or network issue | Ensure tor-proxy service running |
| AI analysis 500 | Missing AI API key / model error | Configure `AI_MODEL_API_KEY` or mock engine |

## 11. Next Steps

Planned enhancements:
- Redis-backed rate limiting & task queues
- Frontend containerization & static asset pipeline
- Advanced investigation visualization (graphs)
- Enhanced auth (refresh tokens, MFA)

---

Maintainer: OSINT Suite Engineering
