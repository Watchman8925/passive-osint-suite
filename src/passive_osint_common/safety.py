"""
Shared Safety Library for Passive OSINT Suite

This module provides common safety helpers for all OSINT modules:
- safe_request: HTTP wrapper with timeouts, retries, and rate-limiting
- input_validation: Decorator for input validation
- handle_exceptions: Structured exception handling decorator
- configure_logger: Standardized logging setup

Usage:
    from src.passive_osint_common.safety import (
        safe_request, input_validation, handle_exceptions, configure_logger
    )
"""

import logging
import time
import functools
from typing import Any, Callable, Optional, TypeVar, cast
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Type variable for generic decorator support
F = TypeVar("F", bound=Callable[..., Any])


def configure_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Configure a standardized logger for modules.

    Args:
        name: Logger name (typically __name__)
        level: Logging level (default: INFO)

    Returns:
        Configured logger instance

    Example:
        logger = configure_logger(__name__)
        logger.info("Module initialized")
    """
    logger = logging.getLogger(name)

    # Only configure if no handlers exist
    if not logger.handlers:
        logger.setLevel(level)

        # Console handler with formatting
        handler = logging.StreamHandler()
        handler.setLevel(level)

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    return logger


# Module logger
logger = configure_logger(__name__)


def safe_request(
    url: str,
    method: str = "GET",
    timeout: int = 30,
    max_retries: int = 3,
    backoff_factor: float = 1.0,
    rate_limit_delay: float = 0.0,
    **kwargs,
) -> Optional[requests.Response]:
    """
    Make a safe HTTP request with timeouts, retries, and rate-limiting.

    Args:
        url: URL to request
        method: HTTP method (GET, POST, etc.)
        timeout: Request timeout in seconds (default: 30)
        max_retries: Maximum number of retries (default: 3)
        backoff_factor: Exponential backoff factor (default: 1.0)
        rate_limit_delay: Delay before request to respect rate limits (default: 0)
        **kwargs: Additional arguments passed to requests.request()

    Returns:
        Response object or None if request fails

    Example:
        response = safe_request("https://api.example.com/data", timeout=10)
        if response and response.ok:
            data = response.json()
    """
    # Validate URL
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            logger.error(f"Invalid URL: {url}")
            return None
    except Exception as e:
        logger.error(f"URL parsing error: {e}")
        return None

    # Rate limiting
    if rate_limit_delay > 0:
        time.sleep(rate_limit_delay)

    # Configure retry strategy
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],
    )

    # Create session with retry adapter
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    try:
        # Ensure timeout is set
        if "timeout" not in kwargs:
            kwargs["timeout"] = timeout

        # Make request
        response = session.request(method, url, **kwargs)

        # Log rate limit headers if present
        if "X-RateLimit-Remaining" in response.headers:
            remaining = response.headers.get("X-RateLimit-Remaining")
            logger.debug(f"Rate limit remaining: {remaining}")

            if int(remaining) < 10:
                logger.warning(f"Rate limit approaching for {url}")

        return response

    except requests.exceptions.Timeout:
        logger.error(f"Request timeout for {url} after {timeout}s")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error for {url}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for {url}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during request to {url}: {e}")
        return None
    finally:
        session.close()


def input_validation(**validators) -> Callable[[F], F]:
    """
    Decorator for input validation with type hints and constraints.

    Args:
        **validators: Validation functions for each parameter
            - For strings: non_empty, min_length, max_length, pattern
            - For numbers: min_value, max_value, positive
            - For URLs: valid_url

    Returns:
        Decorated function with input validation

    Example:
        @input_validation(
            domain=lambda x: isinstance(x, str) and len(x) > 0,
            limit=lambda x: isinstance(x, int) and 0 < x <= 100
        )
        def search_domain(domain: str, limit: int = 10):
            # Function implementation
            pass
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get function signature
            import inspect

            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            # Validate each parameter
            for param_name, validator in validators.items():
                if param_name in bound_args.arguments:
                    value = bound_args.arguments[param_name]

                    try:
                        if not validator(value):
                            raise ValueError(
                                f"Validation failed for parameter '{param_name}' with value '{value}'"
                            )
                    except Exception as e:
                        logger.error(f"Validation error for {param_name}: {e}")
                        raise ValueError(
                            f"Invalid input for parameter '{param_name}': {e}"
                        )

            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator


def handle_exceptions(
    default_return: Any = None, log_traceback: bool = True, reraise: bool = False
) -> Callable[[F], F]:
    """
    Decorator to convert exceptions into structured return values.

    Args:
        default_return: Value to return on exception (default: None)
        log_traceback: Whether to log full traceback (default: True)
        reraise: Whether to re-raise exception after logging (default: False)

    Returns:
        Decorated function with exception handling

    Example:
        @handle_exceptions(default_return={"status": "error"})
        def risky_operation():
            # May raise exceptions
            result = dangerous_call()
            return {"status": "success", "data": result}
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Log the exception
                if log_traceback:
                    logger.exception(f"Exception in {func.__name__}: {e}")
                else:
                    logger.error(f"Exception in {func.__name__}: {e}")

                # Re-raise if requested
                if reraise:
                    raise

                # Return structured error if default_return is a dict
                if isinstance(default_return, dict):
                    return {
                        **default_return,
                        "error": str(e),
                        "error_type": type(e).__name__,
                    }

                return default_return

        return cast(F, wrapper)

    return decorator


# Common validation helpers


def is_non_empty_string(value: Any) -> bool:
    """Check if value is a non-empty string."""
    return isinstance(value, str) and len(value.strip()) > 0


def is_valid_url(value: Any) -> bool:
    """Check if value is a valid URL."""
    if not isinstance(value, str):
        return False

    try:
        result = urlparse(value)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_positive_integer(value: Any) -> bool:
    """Check if value is a positive integer."""
    return isinstance(value, int) and value > 0


def is_in_range(min_val: int, max_val: int) -> Callable[[int], bool]:
    """Create a range validator."""

    def validator(value: int) -> bool:
        return isinstance(value, int) and min_val <= value <= max_val

    return validator


def is_valid_email(value: Any) -> bool:
    """Check if value is a valid email address (basic check)."""
    if not isinstance(value, str):
        return False

    import re

    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def is_valid_domain(value: Any) -> bool:
    """Check if value is a valid domain name."""
    if not isinstance(value, str):
        return False

    import re

    # Basic domain validation
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def is_valid_ip(value: Any) -> bool:
    """Check if value is a valid IP address (v4 or v6)."""
    if not isinstance(value, str):
        return False

    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# Example usage and testing
if __name__ == "__main__":
    # Configure logger
    test_logger = configure_logger(__name__, logging.DEBUG)

    # Test safe_request
    print("\n=== Testing safe_request ===")
    response = safe_request("https://httpbin.org/get", timeout=10)
    if response:
        print(f"✓ Request successful: {response.status_code}")
    else:
        print("✗ Request failed")

    # Test input_validation
    print("\n=== Testing input_validation ===")

    @input_validation(domain=is_valid_domain, limit=is_in_range(1, 100))
    def test_search(domain: str, limit: int = 10):
        return f"Searching {domain} with limit {limit}"

    try:
        result = test_search("example.com", 50)
        print(f"✓ Valid input: {result}")
    except ValueError as e:
        print(f"✗ Validation failed: {e}")

    try:
        result = test_search("invalid domain!", 50)
        print("✗ Should have failed validation")
    except ValueError as e:
        print(f"✓ Correctly rejected invalid input: {e}")

    # Test handle_exceptions
    print("\n=== Testing handle_exceptions ===")

    @handle_exceptions(default_return={"status": "error"})
    def test_risky():
        raise ValueError("Test exception")

    result = test_risky()
    print(f"✓ Exception handled: {result}")

    print("\n=== All tests complete ===")
