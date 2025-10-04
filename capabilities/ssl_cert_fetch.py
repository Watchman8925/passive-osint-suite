from __future__ import annotations

import socket
import ssl
from typing import Any, Dict

from .definitions import CapabilityResult

# Simplistic SSL certificate fetch (no SNI fallback, blocking). Proper implementation will:
# - Handle timeouts
# - Support SNI & alt ports
# - Parse extensions
# - Capture full chain


def execute(context: Dict[str, Any], domain: str, port: int = 443) -> CapabilityResult:
    result = CapabilityResult.start("ssl_cert_fetch")
    try:
        cert_dict = None
        try:
            ctx = ssl.create_default_context()
            # Disable insecure SSL/TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_dict = ssock.getpeercert()
        except Exception as e:  # noqa: BLE001
            result.metrics["cert_error"] = str(e)
        if cert_dict:
            result.produced_entities.append(
                {
                    "type": "ssl_certificate",
                    "subject": cert_dict.get("subject"),
                    "issuer": cert_dict.get("issuer"),
                    "notAfter": cert_dict.get("notAfter"),
                    "notBefore": cert_dict.get("notBefore"),
                    "subjectAltName": cert_dict.get("subjectAltName"),
                    "domain": domain,
                }
            )
        return result.mark_complete(True)
    except Exception as e:  # noqa: BLE001
        return result.mark_complete(False, error=str(e))
