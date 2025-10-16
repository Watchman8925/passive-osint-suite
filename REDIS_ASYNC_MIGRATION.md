# Redis AsyncIO Migration Documentation

## Overview
This document describes the migration from synchronous Redis client to asynchronous Redis client in the OSINT Suite API server.

## Problem Statement
The API server was importing and using the synchronous `redis` client, but some endpoints were attempting to use `await` on Redis methods (e.g., `await app.state.redis.ping()`). This could cause runtime errors or hangs because synchronous methods cannot be awaited.

## Changes Made

### 1. Updated Redis Import (api/api_server.py:95)
**Before:**
```python
import redis  # type: ignore
```

**After:**
```python
import redis.asyncio as redis  # type: ignore
```

### 2. Updated Redis Cleanup Code (api/api_server.py:677-689)
**Before:**
```python
try:
    if getattr(app.state, "redis", None):
        # redis may provide close or connection_pool.close; attempt close gracefully
        close_fn = getattr(app.state.redis, "close", None) or getattr(
            app.state.redis, "connection_pool", None
        )
        try:
            if callable(close_fn):
                close_fn()
            elif hasattr(app.state.redis, "connection_pool") and hasattr(
                app.state.redis.connection_pool, "disconnect"
            ):
                app.state.redis.connection_pool.disconnect()
        except Exception:
            logging.exception("Error closing redis connection")
except Exception:
    logging.exception("Error while cleaning up redis")
```

**After:**
```python
try:
    if getattr(app.state, "redis", None):
        # Close async redis connection
        try:
            # redis.asyncio provides aclose() or close() methods
            if hasattr(app.state.redis, "aclose"):
                await app.state.redis.aclose()
            elif hasattr(app.state.redis, "close"):
                await app.state.redis.close()
        except Exception:
            logging.exception("Error closing redis connection")
except Exception:
    logging.exception("Error while cleaning up redis")
```

## Verification

### Code Already Correctly Using Async (No Changes Needed)

1. **Redis Initialization (api/api_server.py:494):**
   ```python
   app.state.redis = redis.from_url(AppConfig.REDIS_URL) if redis is not None else None
   ```
   The `redis.from_url()` method in `redis.asyncio` returns an async client, so this works correctly.

2. **Health Check Endpoint (api/api_server.py:942):**
   ```python
   await asyncio.wait_for(app.state.redis.ping(), timeout=2.0)
   ```
   This was already correctly using `await`, which will now work properly with the async Redis client.

### Dependencies
The `requirements.txt` already specifies `redis>=5.0.0` (line 60), which includes `redis.asyncio` support. No changes to dependencies were needed.

### Consistency with Other Modules
The `realtime/realtime_feeds.py` module was already using `import redis.asyncio as redis` correctly. The changes to `api/api_server.py` bring it in line with this existing best practice.

## Testing

A test file `tests/test_redis_async.py` has been created to verify:
1. Redis AsyncIO can be imported correctly
2. The api_server.py file uses the async import
3. The api_server.py file uses async close methods
4. Redis async client has expected methods (ping, close/aclose)

Run the test with:
```bash
python3 tests/test_redis_async.py
```

## Benefits

1. **Correctness**: All Redis operations are now properly async, preventing runtime errors
2. **Performance**: Async Redis operations don't block the event loop
3. **Consistency**: All Redis usage across the codebase now follows the same async pattern
4. **Reliability**: Health checks and other Redis operations work correctly without hangs

## Migration Notes

- The async Redis client API is very similar to the sync client, so most code doesn't need changes
- The key difference is that all Redis methods must be awaited
- Connection cleanup must use async methods (`aclose()` or `close()`)
- `redis.from_url()` in `redis.asyncio` automatically returns an async client

## References

- Redis Python Documentation: https://redis-py.readthedocs.io/
- Redis Asyncio Support: https://redis-py.readthedocs.io/en/stable/examples/asyncio_examples.html
