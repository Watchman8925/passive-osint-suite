"""
Passive OSINT Common Library

Shared utilities and safety helpers for all OSINT modules.
"""

from .safety import (
    # Core safety functions
    safe_request,
    input_validation,
    handle_exceptions,
    configure_logger,
    
    # Validation helpers
    is_non_empty_string,
    is_valid_url,
    is_positive_integer,
    is_in_range,
    is_valid_email,
    is_valid_domain,
    is_valid_ip,
)

__all__ = [
    # Core safety functions
    "safe_request",
    "input_validation",
    "handle_exceptions",
    "configure_logger",
    
    # Validation helpers
    "is_non_empty_string",
    "is_valid_url",
    "is_positive_integer",
    "is_in_range",
    "is_valid_email",
    "is_valid_domain",
    "is_valid_ip",
]

__version__ = "1.0.0"
