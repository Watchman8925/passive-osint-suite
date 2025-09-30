from __future__ import annotations

import socket
from typing import Any, Dict

from .definitions import CapabilityResult

# Very lightweight DNS A record lookup (blocking). In future convert to async & add error handling.


def execute(context: Dict[str, Any], domain: str) -> CapabilityResult:
    result = CapabilityResult.start("dns_basic")
    try:
        addresses = []
        try:
            for ai in socket.getaddrinfo(domain, None):
                ip = ai[4][0]
                if ip not in addresses:
                    addresses.append(ip)
        except Exception as e:  # noqa: BLE001
            # Partial failure allowed
            result.metrics["lookup_error"] = str(e)
        # Entities
        result.produced_entities.append(
            {
                "type": "domain",
                "value": domain,
                "addresses": addresses,
            }
        )
        # Relationships (domain -> ip)
        for ip in addresses:
            result.produced_relationships.append(
                {
                    "type": "RESOLVES_TO",
                    "source": ("domain", domain),
                    "target": ("ip", ip),
                }
            )
        result.metrics["ip_count"] = len(addresses)
        return result.mark_complete(True)
    except Exception as e:  # noqa: BLE001
        return result.mark_complete(False, error=str(e))
