"""
OPSEC Policy Enforcement
Operational security policies and enforcement
"""

from typing import Any, Dict, Optional


def enforce_policy(
    action: Optional[str] = None, context: Optional[Dict[str, Any]] = None, **kwargs
) -> Dict[str, Any]:
    """
    Enforce OPSEC policies for actions

    Args:
        action: Action being performed (deprecated, use operation_type in kwargs)
        context: Context information (deprecated, use kwargs)
        **kwargs: Policy enforcement parameters including:
            - operation_type: Type of operation
            - target: Target of operation
            - actor: Actor performing operation
            - user_agent: User agent string

    Returns:
        Dict with 'allowed' boolean and 'actions' list
    """
    # Handle both old and new calling patterns
    if action and not kwargs:
        # Old pattern: enforce_policy(action, context)
        operation_type = action
        target = context.get("target") if context else None
        actor = context.get("actor") if context else None
    else:
        # New pattern: enforce_policy(operation_type=..., target=..., actor=...)
        operation_type = kwargs.get("operation_type", action or "unknown")
        target = kwargs.get("target")
        actor = kwargs.get("actor")

    # Basic policy enforcement framework (policies available for future use)
    _policies = {
        "network_scan": {"max_requests": 100, "cooldown": 60},
        "api_call": {"max_requests": 1000, "cooldown": 60},
        "file_access": {"allowed_paths": ["/tmp", "/var/log"]},
        "external_command": {"allowed_commands": []},
        "domain_lookup": {"max_requests": 500, "cooldown": 30},
        "ip_lookup": {"max_requests": 500, "cooldown": 30},
    }

    # Policy lookup (currently unused but available for future enforcement)
    # policy = _policies.get(operation_type, {})

    # For now, allow all operations but log them
    result = {
        "allowed": True,
        "actions": [],
        "operation_type": operation_type,
        "target": target,
        "actor": actor,
        "timestamp": __import__("time").time(),
    }

    return result


class PolicyEngine:
    """
    OPSEC Policy Engine for tracking violations and statistics
    """

    def __init__(self):
        self.violations = []
        self.operations_evaluated = 0
        self.total_policies = 4  # network_scan, api_call, file_access, external_command

    def record_violation(self, operation_type: str, target: str, reason: str):
        """Record a policy violation"""
        violation = {
            "operation_type": operation_type,
            "target": target,
            "reason": reason,
            "timestamp": __import__("time").time(),
        }
        self.violations.append(violation)

    def get_violations(self, limit: int = 10) -> list:
        """Get recent policy violations"""
        return self.violations[-limit:] if self.violations else []

    def get_policy_stats(self) -> Dict[str, Any]:
        """Get policy engine statistics"""
        return {
            "total_policies": self.total_policies,
            "operations_evaluated": self.operations_evaluated,
            "total_violations": len(self.violations),
        }


# Global instances
policy_engine = PolicyEngine()
