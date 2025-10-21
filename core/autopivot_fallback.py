"""Deterministic fallback engine for autopivot endpoints.

This module provides a lightweight, deterministic autopivot engine that does
not rely on external LLM providers. It leverages the offline LLM engine when
available to extract structured leads and falls back to rule-based heuristics
when no rich investigation data exists. The implementation mirrors the async
interface expected by the primary AI engine so the API handlers can seamlessly
swap in this engine when ``app.state.ai_engine`` is unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from core.offline_llm_engine import get_offline_llm_engine
except Exception:  # pragma: no cover - defensive import for minimal envs
    get_offline_llm_engine = None  # type: ignore

logger = logging.getLogger(__name__)


class DeterministicAutopivotEngine:
    """Offline-friendly autopivot engine with deterministic suggestions."""

    def __init__(self) -> None:
        self._offline_engine = None
        if get_offline_llm_engine is not None:
            try:
                self._offline_engine = get_offline_llm_engine()
            except Exception:  # pragma: no cover - defensive guard
                logger.exception("Failed to initialize offline LLM engine")
                self._offline_engine = None

    async def suggest_autopivots(
        self, investigation_data: Dict[str, Any], max_pivots: int = 5
    ) -> List[Dict[str, Any]]:
        """Return deterministic pivot suggestions for the investigation."""

        pivots: List[Dict[str, Any]] = []

        # Prefer leads already captured in the investigation record.
        analysis_section = investigation_data.get("ai_analysis", {})
        pivots.extend(self._pivots_from_analysis_sections(analysis_section))

        has_structured_data = bool(analysis_section) or bool(
            investigation_data.get("results")
        )

        # Use offline engine analysis if available and no pivots yet.
        if not pivots and self._offline_engine is not None and has_structured_data:
            try:
                analysis_result = await asyncio.to_thread(
                    self._offline_engine.analyze_investigation_data,
                    investigation_data,
                    "comprehensive",
                )
                pivots.extend(self._pivots_from_leads(analysis_result.investigation_leads))
                pivots.extend(self._pivots_from_entities(analysis_result.entities_found))
            except Exception as exc:  # pragma: no cover - logging only
                logger.warning("Offline analysis failed: %s", exc)

        # Heuristic extraction from raw investigation data.
        if not pivots:
            pivots.extend(self._pivots_from_entities(self._extract_entities(investigation_data)))

        # Ensure we always have at least one actionable suggestion.
        if not pivots:
            pivots.extend(self._heuristic_pivots_from_targets(investigation_data))

        # Deduplicate pivots by target/type tuple while preserving order.
        unique: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for pivot in pivots:
            target = pivot.get("target")
            target_type = pivot.get("target_type") or pivot.get("type")
            if not target or not target_type:
                continue
            key = (str(target), str(target_type))
            if key not in unique:
                normalized = dict(pivot)
                normalized.setdefault("target_type", str(target_type))
                normalized.setdefault("confidence", 0.65)
                normalized.setdefault("priority", "medium")
                normalized.setdefault(
                    "recommended_modules", self._modules_for_type(str(target_type))
                )
                normalized.setdefault("source", "offline-deterministic")
                normalized.setdefault(
                    "reason",
                    "Deterministic heuristic suggestion based on investigation data",
                )
                unique[key] = normalized

        return list(unique.values())[:max_pivots]

    async def execute_autonomous_investigation(
        self,
        initial_target: str,
        target_type: str,
        max_depth: int = 3,
        max_pivots_per_level: int = 3,
    ) -> Dict[str, Any]:
        """Perform a deterministic autonomous investigation."""

        investigation_tree = {
            "initial_target": initial_target,
            "target_type": target_type,
            "started_at": datetime.utcnow().isoformat(),
            "levels": [],
            "total_targets_investigated": 0,
            "total_pivots": 0,
        }

        queue: List[Tuple[str, str, int]] = [(initial_target, target_type, 0)]
        visited: set[Tuple[str, str]] = set()

        while queue and investigation_tree["total_targets_investigated"] < 100:
            target, ttype, depth = queue.pop(0)
            key = (target, ttype)
            if depth >= max_depth or key in visited:
                continue
            visited.add(key)
            investigation_tree["total_targets_investigated"] += 1

            investigation_snapshot = {
                "name": f"Autonomous investigation of {target}",
                "targets": [target],
                "investigation_type": ttype,
            }

            pivots = await self.suggest_autopivots(
                investigation_data=investigation_snapshot,
                max_pivots=max_pivots_per_level,
            )

            node = {
                "target": target,
                "target_type": ttype,
                "depth": depth,
                "results": {},
                "pivots": pivots,
            }

            investigation_tree["total_pivots"] += len(pivots)

            while len(investigation_tree["levels"]) <= depth:
                investigation_tree["levels"].append([])
            investigation_tree["levels"][depth].append(node)

            for pivot in pivots:
                if pivot.get("priority") in ("high", "medium"):
                    queue.append(
                        (
                            str(pivot.get("target")),
                            str(pivot.get("target_type") or pivot.get("type") or "domain"),
                            depth + 1,
                        )
                    )

        investigation_tree["completed_at"] = datetime.utcnow().isoformat()
        return investigation_tree

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _pivots_from_analysis_sections(self, analysis: Any) -> List[Dict[str, Any]]:
        pivots: List[Dict[str, Any]] = []
        if isinstance(analysis, dict):
            for section in analysis.values():
                if isinstance(section, dict):
                    pivots.extend(
                        self._pivots_from_leads(section.get("investigation_leads", []))
                    )
                    pivots.extend(
                        self._pivots_from_entities(section.get("entities_found", []))
                    )
        return pivots

    def _pivots_from_leads(self, leads: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        pivots: List[Dict[str, Any]] = []
        for lead in leads or []:
            target = lead.get("target")
            if not target:
                continue
            target_type = lead.get("type") or lead.get("target_type")
            pivots.append(
                {
                    "target": str(target),
                    "target_type": self._normalize_target_type(target_type),
                    "reason": lead.get("reason")
                    or "Lead extracted from offline analysis results",
                    "priority": lead.get("priority", "medium"),
                    "confidence": lead.get("confidence", 0.7),
                    "recommended_modules": lead.get("modules")
                    or self._modules_for_type(self._normalize_target_type(target_type)),
                }
            )
        return pivots

    def _pivots_from_entities(self, entities: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        pivots: List[Dict[str, Any]] = []
        for entity in entities or []:
            value = entity.get("value") or entity.get("target")
            if not value:
                continue
            entity_type = entity.get("type") or entity.get("target_type")
            pivots.append(
                {
                    "target": str(value),
                    "target_type": self._normalize_target_type(entity_type),
                    "reason": self._reason_for_type(self._normalize_target_type(entity_type)),
                    "priority": "medium",
                    "confidence": 0.6,
                    "recommended_modules": self._modules_for_type(
                        self._normalize_target_type(entity_type)
                    ),
                }
            )
        return pivots

    def _heuristic_pivots_from_targets(self, investigation: Dict[str, Any]) -> List[Dict[str, Any]]:
        pivots: List[Dict[str, Any]] = []
        for target in investigation.get("targets", []) or []:
            guess = self._normalize_target_type(self._guess_target_type(str(target)))
            if guess == "domain":
                pivots.append(
                    {
                        "target": f"mail.{target}",
                        "target_type": "domain",
                        "reason": "Investigate potential mail subdomain for infrastructure insights",
                        "priority": "high",
                        "confidence": 0.55,
                        "recommended_modules": ["subdomain_enum", "dns_intel"],
                    }
                )
                pivots.append(
                    {
                        "target": str(target).split(".", 1)[-1],
                        "target_type": "domain",
                        "reason": "Check parent domain for broader organizational footprint",
                        "priority": "medium",
                        "confidence": 0.5,
                        "recommended_modules": ["domain_recon"],
                    }
                )
            elif guess == "email":
                local, _, domain = str(target).partition("@")
                if domain:
                    pivots.append(
                        {
                            "target": domain,
                            "target_type": "domain",
                            "reason": "Pivot to email's domain to discover hosted services",
                            "priority": "high",
                            "confidence": 0.6,
                            "recommended_modules": ["domain_recon", "dns_intel"],
                        }
                    )
                if local:
                    pivots.append(
                        {
                            "target": local,
                            "target_type": "username",
                            "reason": "Investigate username reuse across platforms",
                            "priority": "medium",
                            "confidence": 0.55,
                            "recommended_modules": ["social_media_footprint", "breach_search"],
                        }
                    )
            elif guess == "ip":
                prefix = ".".join(str(target).split(".")[:3])
                pivots.append(
                    {
                        "target": f"{prefix}.0/24",
                        "target_type": "network",
                        "reason": "Scan the surrounding /24 network range for related hosts",
                        "priority": "high",
                        "confidence": 0.6,
                        "recommended_modules": ["network_analysis", "ip_intel"],
                    }
                )
        return pivots

    def _modules_for_type(self, entity_type: str) -> List[str]:
        module_map = {
            "email": ["email_intel", "breach_search", "social_media_footprint"],
            "domain": ["domain_recon", "dns_intel", "subdomain_enum"],
            "ip": ["ip_intel", "network_analysis"],
            "username": ["social_media_footprint", "username_lookup"],
            "phone": ["phone_intel", "geospatial_intel"],
            "network": ["network_analysis", "ip_intel"],
        }
        return module_map.get(entity_type, ["domain_recon"])

    def _normalize_target_type(self, target_type: Optional[str]) -> str:
        valid_types = {"domain", "email", "ip", "username", "phone", "network"}
        if target_type and target_type in valid_types:
            return target_type
        return "domain"

    def _reason_for_type(self, entity_type: str) -> str:
        reasons = {
            "email": "Email addresses often reveal breaches and associated accounts",
            "domain": "Domains expose related infrastructure and subdomains",
            "ip": "IP intelligence highlights hosting providers and exposed services",
            "username": "Usernames can be correlated across different platforms",
            "phone": "Phone numbers may connect to individuals or businesses",
            "network": "Networks provide breadth to uncover related hosts",
        }
        return reasons.get(entity_type, "Entity provides additional investigative context")

    def _guess_target_type(self, target: str) -> str:
        if "@" in target:
            return "email"
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", target):
            return "ip"
        if re.match(r"^[+\d][\d\- ]{6,}$", target):
            return "phone"
        if re.match(r"^[A-Za-z0-9_.-]{3,}$", target) and "." not in target:
            return "username"
        return "domain"

    def _extract_entities(self, investigation_data: Dict[str, Any]) -> List[Dict[str, str]]:
        entities: List[Dict[str, str]] = []
        raw_sources = []
        if isinstance(investigation_data.get("results"), dict):
            raw_sources.append(investigation_data["results"])
        if isinstance(investigation_data.get("ai_analysis"), dict):
            raw_sources.append(investigation_data["ai_analysis"])
        text = " ".join(str(source) for source in raw_sources)
        if not text:
            return entities

        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        domain_pattern = r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

        for email in re.findall(email_pattern, text):
            entities.append({"type": "email", "value": email})
        for domain in re.findall(domain_pattern, text):
            if "@" not in domain:
                entities.append({"type": "domain", "value": domain})
        for ip in re.findall(ip_pattern, text):
            entities.append({"type": "ip", "value": ip})

        seen: set[Tuple[str, str]] = set()
        unique_entities: List[Dict[str, str]] = []
        for entity in entities:
            key = (entity["type"], entity["value"])
            if key not in seen:
                seen.add(key)
                unique_entities.append(entity)
        return unique_entities


__all__ = ["DeterministicAutopivotEngine"]
