"""
Rate Limiting System for OSINT Suite
Respect API limits and prevent blocking
"""

import threading
import time
from typing import Dict, Optional

from utils.osint_utils import OSINTUtils


class RateLimiter:
    """Rate limiter using token bucket algorithm"""

    def __init__(self, rate_per_minute: int = 60):
        self.rate_per_minute = rate_per_minute
        self.tokens = rate_per_minute
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def acquire(self, tokens: int = 1) -> bool:
        """Acquire tokens from the bucket"""
        with self.lock:
            self._refill_tokens()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            return False

    def _refill_tokens(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill
        refill_amount = int(elapsed * (self.rate_per_minute / 60))

        if refill_amount > 0:
            self.tokens = min(self.rate_per_minute, self.tokens + refill_amount)
            self.last_refill = now

    def wait_for_tokens(self, tokens: int = 1, timeout: float = 60.0) -> bool:
        """Wait for tokens to become available"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            if self.acquire(tokens):
                return True
            time.sleep(0.1)  # Small delay to prevent busy waiting

        return False

class ServiceRateLimiter:
    """Rate limiter for external services"""

    def __init__(self):
        self.utils = OSINTUtils()
        self.limiters: Dict[str, RateLimiter] = {}
        self._lock = threading.RLock()

        # Load service rate limits from service registry
        self._load_service_limits()

    def _load_service_limits(self):
        """Load rate limits from service registry"""
        try:
            from utils.service_registry import service_registry

            for service_name in service_registry.list_all_services():
                rate_limit = service_registry.get_rate_limit(service_name)
                if rate_limit > 0:
                    self.limiters[service_name] = RateLimiter(rate_limit)

        except ImportError:
            # Fallback to default limits
            self._set_default_limits()

    def _set_default_limits(self):
        """Set default rate limits for common services"""
        default_limits = {
            'shodan': 1,
            'alienvault': 2,
            'greynoise': 10,
            'virustotal': 4,
            'securitytrails': 1,
            'hostio': 10,
            'projectdiscovery': 5,
            'intelx': 2,
            'hunter': 10,
            'googlesearch': 100,
            'etherscan': 5,
            'coinmarketcap': 10,
            'flightaware': 1,
            'opencage': 2500,
            'mapbox': 60000
        }

        for service, limit in default_limits.items():
            self.limiters[service] = RateLimiter(limit)

    def check_rate_limit(self, service_name: str, tokens: int = 1) -> bool:
        """Check if request can proceed within rate limits"""
        with self._lock:
            limiter = self.limiters.get(service_name)
            if limiter:
                return limiter.acquire(tokens)
            else:
                # No rate limit configured, allow request
                return True

    def wait_for_rate_limit(self, service_name: str, tokens: int = 1, timeout: float = 60.0) -> bool:
        """Wait for rate limit to allow request"""
        with self._lock:
            limiter = self.limiters.get(service_name)
            if limiter:
                return limiter.wait_for_tokens(tokens, timeout)
            else:
                # No rate limit configured, allow request
                return True

    def get_remaining_tokens(self, service_name: str) -> int:
        """Get remaining tokens for a service"""
        limiter = self.limiters.get(service_name)
        if limiter:
            limiter._refill_tokens()  # Ensure up to date
            return limiter.tokens
        return -1  # Unlimited

    def get_rate_limit_info(self, service_name: str) -> Dict:
        """Get rate limit information for a service"""
        limiter = self.limiters.get(service_name)
        if limiter:
            limiter._refill_tokens()  # Ensure up to date
            return {
                'service': service_name,
                'rate_per_minute': limiter.rate_per_minute,
                'available_tokens': limiter.tokens,
                'limited': True
            }
        else:
            return {
                'service': service_name,
                'rate_per_minute': -1,
                'available_tokens': -1,
                'limited': False
            }

class RequestThrottler:
    """Throttle requests to prevent overwhelming services"""

    def __init__(self, min_interval: float = 0.1):
        self.min_interval = min_interval
        self.last_request_time = 0
        self.lock = threading.Lock()

    def throttle(self):
        """Throttle request to maintain minimum interval"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request_time

            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)

            self.last_request_time = time.time()

class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on API responses"""

    def __init__(self, service_name: str, base_rate: int = 60):
        self.service_name = service_name
        self.base_rate = base_rate
        self.current_rate = base_rate
        self.backoff_until = 0
        self.consecutive_errors = 0
        self.lock = threading.RLock()

    def record_success(self):
        """Record successful API call"""
        with self._lock:
            self.consecutive_errors = 0
            # Gradually increase rate on success
            if self.current_rate < self.base_rate:
                self.current_rate = min(self.base_rate, int(self.current_rate * 1.1))

    def record_error(self, retry_after: Optional[int] = None):
        """Record API error"""
        with self._lock:
            self.consecutive_errors += 1

            if retry_after:
                self.backoff_until = time.time() + retry_after
            else:
                # Exponential backoff
                backoff_time = min(300, 2 ** self.consecutive_errors)  # Max 5 minutes
                self.backoff_until = time.time() + backoff_time

            # Reduce rate on errors
            self.current_rate = max(1, int(self.current_rate * 0.5))

    def can_make_request(self) -> bool:
        """Check if request can be made"""
        with self._lock:
            now = time.time()

            # Check backoff period
            if now < self.backoff_until:
                return False

            # Check rate limit
            # This is a simplified implementation - in practice you'd track request times
            return True

    def get_effective_rate(self) -> int:
        """Get current effective rate limit"""
        with self._lock:
            return self.current_rate

# Global rate limiting instances
service_rate_limiter = ServiceRateLimiter()
request_throttler = RequestThrottler()

def rate_limited(service_name: str, tokens: int = 1):
    """
    Decorator to enforce rate limiting

    Usage:
        @rate_limited('shodan')
        def api_call():
            return make_request()
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not service_rate_limiter.check_rate_limit(service_name, tokens):
                raise Exception(f"Rate limit exceeded for {service_name}")

            # Add throttling
            request_throttler.throttle()

            return func(*args, **kwargs)

        return wrapper
    return decorator

def wait_for_rate_limit(service_name: str, tokens: int = 1, timeout: float = 60.0):
    """Wait for rate limit to allow request"""
    return service_rate_limiter.wait_for_rate_limit(service_name, tokens, timeout)