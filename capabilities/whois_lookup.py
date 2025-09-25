from __future__ import annotations

from typing import Any, Dict

from .definitions import CapabilityResult

# Placeholder: real WHOIS would use a library (python-whois) with rate-limit & parsing.

def execute(context: Dict[str, Any], domain: str) -> CapabilityResult:
    result = CapabilityResult.start("whois_lookup")
    try:
        # Stubbed pseudo output (later replace with real whois data + normalization)
        result.produced_entities.append({
            "type": "domain",
            "value": domain,
            "whois_stub": True,
        })
        result.metrics["whois"] = "stub"
        return result.mark_complete(True)
    except Exception as e:  # noqa: BLE001
        return result.mark_complete(False, error=str(e))
