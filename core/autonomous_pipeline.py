"""Evidence-driven autonomous investigation pipeline.

This module stitches together real collectors, persistent storage, and the
knowledge graph so autopivoting becomes data-backed instead of heuristic. The
pipeline exposes a small surface area that higher level engines (such as the
`LocalLLMEngine`) can delegate to.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

import requests

from core.investigation_tracker import InvestigationTracker
from evidence.store import EvidenceRecord, EvidenceStore, get_default_store
from graph.adapter import GraphAdapter, get_default_graph

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _serialize(data: Any) -> str:
    try:
        return json.dumps(data, ensure_ascii=False, default=str)
    except Exception:  # pragma: no cover - safeguard for unexpected data
        return json.dumps({"unserializable": str(type(data))})


@dataclass
class CollectorResult:
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw: Any = field(default_factory=dict)
    summary: str = ""


class MultiINTCollector:
    """Run multi-intelligence collection with open, credential-free sources."""

    def __init__(
        self,
        tracker: Optional[InvestigationTracker] = None,
        evidence_store: Optional[EvidenceStore] = None,
        graph: Optional[GraphAdapter] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.tracker = tracker or InvestigationTracker()
        self.evidence_store = evidence_store or get_default_store()
        self.graph = graph or get_default_graph()
        self.session = session or requests.Session()
        self.session.headers.setdefault(
            "User-Agent",
            "Passive-OSINT-Suite/1.0 (+https://github.com/pacifichackers/passive-osint-suite)",
        )

    async def collect(
        self, investigation_id: str, target: str, target_type: str
    ) -> Dict[str, Any]:
        """Execute collection workflow for the given target."""

        logger.info(
            "Starting multi-INT collection",
            extra={"investigation_id": investigation_id, "target": target},
        )

        self.graph.upsert_entity(
            "investigation", investigation_id, {"last_collected": _utcnow().isoformat()}
        )

        plan = self._build_plan(target, target_type)
        steps: List[Dict[str, Any]] = []

        for name, func in plan:
            started = _utcnow()
            logger.debug(f"Running collector {name} for {target}")
            try:
                result: CollectorResult = await asyncio.to_thread(func)
                status = "success"
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning(f"Collector {name} failed for {target}: {exc}")
                result = CollectorResult(
                    findings=[], raw={"error": str(exc)}, summary=str(exc)
                )
                status = "error"

            evidence_record: Optional[EvidenceRecord] = None
            if result.raw:
                try:
                    evidence_record = self.evidence_store.save(
                        _serialize(result.raw),
                        investigation_id=investigation_id,
                        capability_id=name,
                        artifact_type="json",
                        tags={"target": target, "target_type": target_type},
                        suggested_name=f"{investigation_id}_{name}_{int(time.time())}.json",
                    )
                except Exception as exc:  # pragma: no cover - logging safeguard
                    logger.error(f"Failed to persist evidence for {name}: {exc}")

            finding_ids: List[str] = []
            for finding in result.findings:
                recorded = self._record_finding(
                    investigation_id, target, target_type, name, finding
                )
                if recorded:
                    finding_ids.append(recorded)

            completed = _utcnow()
            steps.append(
                {
                    "module": name,
                    "status": status,
                    "summary": result.summary,
                    "finding_ids": finding_ids,
                    "evidence_id": evidence_record.evidence_id
                    if evidence_record is not None
                    else None,
                    "started_at": started.isoformat(),
                    "completed_at": completed.isoformat(),
                }
            )

        return {
            "target": target,
            "target_type": target_type,
            "steps": steps,
        }

    def _build_plan(self, target: str, target_type: str) -> List[Tuple[str, Callable[[], CollectorResult]]]:
        plan: List[Tuple[str, Callable[[], CollectorResult]]] = []

        if target_type in {"domain", "subdomain"}:
            plan.append(("crt_sh", lambda: self._collect_crtsh(target)))
            plan.append(("dns_google", lambda: self._collect_dns_records(target)))
            plan.append(("wayback", lambda: self._collect_wayback(target)))
            plan.append(("duckduckgo_domain", lambda: self._collect_duckduckgo(target)))
        elif target_type == "email":
            plan.append(("gravatar", lambda: self._collect_gravatar(target)))
            plan.append(("duckduckgo_email", lambda: self._collect_duckduckgo(target)))
        elif target_type == "ip":
            plan.append(("ip_api", lambda: self._collect_ip_api(target)))
            plan.append(("duckduckgo_ip", lambda: self._collect_duckduckgo(target)))
        elif target_type == "username":
            plan.append(("github_user", lambda: self._collect_github_user(target)))
            plan.append(("duckduckgo_username", lambda: self._collect_duckduckgo(target)))
        else:
            plan.append(("duckduckgo_generic", lambda: self._collect_duckduckgo(target)))

        return plan

    def _record_finding(
        self,
        investigation_id: str,
        target: str,
        target_type: str,
        source_module: str,
        finding: Dict[str, Any],
    ) -> Optional[str]:
        value = finding.get("value")
        finding_type = finding.get("type")
        if not value or not finding_type:
            return None

        confidence = float(finding.get("confidence", 0.5))
        metadata = dict(finding.get("metadata", {}))
        metadata.setdefault("source_target", target)
        metadata.setdefault("source_target_type", target_type)

        finding_id = self.tracker.add_finding(
            investigation_id=investigation_id,
            finding_type=finding_type,
            value=value,
            source_module=source_module,
            confidence=confidence,
            metadata=metadata,
        )

        if finding_id:
            entity_type = finding.get("graph_type", finding_type)
            entity = self.graph.upsert_entity(
                entity_type,
                value,
                {
                    "last_seen": _utcnow().isoformat(),
                    "confidence": confidence,
                    "sources": metadata.get("sources", [source_module]),
                },
            )
            self.graph.link(
                ("investigation", investigation_id),
                (entity.type, entity.key),
                "OBSERVED",
                {"module": source_module, "confidence": confidence},
            )

        return finding_id

    # --- individual collectors -------------------------------------------------

    def _collect_crtsh(self, domain: str) -> CollectorResult:
        url = "https://crt.sh/"
        params = {"q": domain, "output": "json"}
        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        findings: List[Dict[str, Any]] = []
        seen: set[str] = set()

        for entry in data:
            name_value = entry.get("name_value", "")
            for candidate in {p.strip().lower() for p in name_value.split("\n") if p.strip()}:
                if candidate in seen:
                    continue
                seen.add(candidate)
                finding_type = "domain" if candidate == domain else "subdomain"
                findings.append(
                    {
                        "type": finding_type,
                        "value": candidate,
                        "confidence": 0.9,
                        "metadata": {
                            "issuer_ca_id": entry.get("issuer_ca_id"),
                            "not_before": entry.get("not_before"),
                            "not_after": entry.get("not_after"),
                        },
                    }
                )

        summary = f"Extracted {len(findings)} certificate subjects from crt.sh"
        return CollectorResult(findings=findings, raw=data, summary=summary)

    def _collect_dns_records(self, domain: str) -> CollectorResult:
        response = self.session.get(
            "https://dns.google/resolve", params={"name": domain, "type": "ANY"}, timeout=20
        )
        response.raise_for_status()
        data = response.json()

        answers = data.get("Answer", []) or []
        findings: List[Dict[str, Any]] = []
        type_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}

        for answer in answers:
            record_type = type_map.get(answer.get("type"), "OTHER")
            record_data = answer.get("data")
            confidence = 0.75 if record_type in {"A", "AAAA", "MX"} else 0.6
            if record_type in {"A", "AAAA"}:
                finding_type = "ip"
                graph_type = "ip"
            elif record_type in {"MX", "NS", "CNAME"}:
                finding_type = "domain"
                graph_type = "domain"
            else:
                finding_type = "dns_record"
                graph_type = "dns_record"

            findings.append(
                {
                    "type": finding_type,
                    "value": record_data,
                    "confidence": confidence,
                    "graph_type": graph_type,
                    "metadata": {"dns_type": record_type},
                }
            )

        summary = f"Resolved {len(answers)} DNS records via dns.google"
        return CollectorResult(findings=findings, raw=data, summary=summary)

    def _collect_wayback(self, domain: str) -> CollectorResult:
        response = self.session.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}",
                "output": "json",
                "limit": 40,
                "filter": "statuscode:200",
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()

        findings: List[Dict[str, Any]] = []
        for row in data[1:]:  # first row is header
            original = row[2]
            findings.append(
                {
                    "type": "url",
                    "value": original,
                    "confidence": 0.55,
                    "metadata": {"timestamp": row[1], "mime": row[3]},
                }
            )

        summary = f"Archived URLs discovered via Wayback Machine: {len(findings)}"
        return CollectorResult(findings=findings, raw=data, summary=summary)

    def _collect_duckduckgo(self, query: str) -> CollectorResult:
        response = self.session.get(
            "https://duckduckgo.com/",
            params={"q": query, "format": "json", "no_redirect": "1", "no_html": "1"},
            timeout=20,
        )
        response.raise_for_status()
        try:
            data = response.json()
        except ValueError:
            data = {}

        related_topics = data.get("RelatedTopics", [])
        findings: List[Dict[str, Any]] = []

        for topic in related_topics:
            if "FirstURL" not in topic:
                continue
            findings.append(
                {
                    "type": "intel_reference",
                    "value": topic["FirstURL"],
                    "confidence": 0.5,
                    "metadata": {"snippet": topic.get("Text")},
                }
            )

        summary = f"DuckDuckGo references retrieved: {len(findings)}"
        return CollectorResult(findings=findings, raw=data, summary=summary)

    def _collect_gravatar(self, email: str) -> CollectorResult:
        email_normalized = email.strip().lower()
        email_hash = hashlib.md5(email_normalized.encode("utf-8")).hexdigest()
        avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        response = self.session.get(avatar_url, timeout=10)

        findings: List[Dict[str, Any]] = []
        if response.status_code == 200:
            profile_url = f"https://www.gravatar.com/{email_hash}"
            findings.append(
                {
                    "type": "profile",
                    "value": profile_url,
                    "confidence": 0.7,
                    "metadata": {
                        "hash": email_hash,
                        "content_length": response.headers.get("Content-Length"),
                    },
                }
            )
            summary = "Gravatar profile located"
        else:
            summary = "No Gravatar profile"

        raw = {"status_code": response.status_code, "hash": email_hash}
        return CollectorResult(findings=findings, raw=raw, summary=summary)

    def _collect_ip_api(self, ip: str) -> CollectorResult:
        response = self.session.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,city,isp,org,as,query,lat,lon,reverse"},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()

        findings: List[Dict[str, Any]] = []
        if data.get("status") == "success":
            geo = ", ".join(
                part
                for part in [data.get("city"), data.get("country")] if part and part != "None"
            )
            if geo:
                findings.append(
                    {
                        "type": "geolocation",
                        "value": geo,
                        "confidence": 0.75,
                        "metadata": {"latitude": data.get("lat"), "longitude": data.get("lon")},
                    }
                )
            if data.get("isp"):
                findings.append(
                    {
                        "type": "service_provider",
                        "value": data["isp"],
                        "confidence": 0.65,
                        "metadata": {"org": data.get("org"), "asn": data.get("as")},
                    }
                )
            if data.get("reverse"):
                findings.append(
                    {
                        "type": "domain",
                        "value": data["reverse"],
                        "confidence": 0.6,
                        "metadata": {"source": "reverse_dns"},
                    }
                )
            summary = "IP geolocation retrieved"
        else:
            summary = f"ip-api reported error: {data.get('message', 'unknown')}"

        return CollectorResult(findings=findings, raw=data, summary=summary)

    def _collect_github_user(self, username: str) -> CollectorResult:
        response = self.session.get(
            f"https://api.github.com/users/{quote_plus(username)}", timeout=15
        )
        if response.status_code == 404:
            return CollectorResult(findings=[], raw={"status": 404}, summary="GitHub user not found")
        response.raise_for_status()
        data = response.json()

        findings: List[Dict[str, Any]] = []
        findings.append(
            {
                "type": "profile",
                "value": data.get("html_url"),
                "confidence": 0.7,
                "metadata": {
                    "followers": data.get("followers"),
                    "public_repos": data.get("public_repos"),
                },
            }
        )
        if data.get("company"):
            findings.append(
                {
                    "type": "company",
                    "value": data["company"],
                    "confidence": 0.5,
                    "metadata": {"source": "github"},
                }
            )

        summary = "GitHub account intelligence gathered"
        return CollectorResult(findings=findings, raw=data, summary=summary)


class EvidenceDrivenPivotPlanner:
    """Translate stored findings into prioritized pivot opportunities."""

    RECOMMENDED_MODULES: Dict[str, List[str]] = {
        "domain": ["domain_recon", "dns_intelligence", "passive_dns_enum"],
        "subdomain": ["domain_recon", "web_discovery"],
        "email": ["email_intel", "public_breach_search"],
        "ip": ["ip_intel", "network_analysis"],
        "profile": ["social_media_footprint", "comprehensive_social_passive"],
        "geolocation": ["geospatial_intel"],
        "company": ["company_intel", "financial_intel"],
    }

    def __init__(
        self,
        tracker: Optional[InvestigationTracker] = None,
        graph: Optional[GraphAdapter] = None,
    ) -> None:
        self.tracker = tracker or InvestigationTracker()
        self.graph = graph or get_default_graph()

    def generate_pivots(
        self, investigation_id: str, *, max_pivots: int = 5
    ) -> List[Dict[str, Any]]:
        findings = self.tracker.get_all_findings(investigation_id)
        if not findings:
            return []

        grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for finding in findings:
            pivot_type = self._normalize_finding_type(finding.finding_type)
            if not pivot_type:
                continue
            key = (pivot_type, finding.value)
            bucket = grouped.setdefault(
                key,
                {
                    "confidence_scores": [],
                    "sources": set(),
                    "latest_seen": datetime.min.replace(tzinfo=timezone.utc),
                },
            )
            bucket["confidence_scores"].append(float(finding.confidence))
            bucket["sources"].add(finding.source_module)
            try:
                seen = datetime.fromisoformat(finding.discovered_at)
                if seen.tzinfo is None:
                    seen = seen.replace(tzinfo=timezone.utc)
                else:
                    seen = seen.astimezone(timezone.utc)
            except ValueError:
                seen = _utcnow()
            if seen > bucket["latest_seen"]:
                bucket["latest_seen"] = seen

        pivots: List[Dict[str, Any]] = []
        for (pivot_type, value), bucket in grouped.items():
            avg_conf = sum(bucket["confidence_scores"]) / max(1, len(bucket["confidence_scores"]))
            source_count = len(bucket["sources"])
            hours_old = max(0.0, (_utcnow() - bucket["latest_seen"]).total_seconds() / 3600.0)
            freshness_bonus = max(0.0, 0.25 - min(hours_old / 48.0, 1.0) * 0.25)

            graph_edges = list(self.graph.neighbors(pivot_type, value))
            connectivity_bonus = min(0.25, 0.05 * len(graph_edges))

            score = min(1.0, avg_conf + 0.1 * source_count + freshness_bonus + connectivity_bonus)
            priority = self._priority_from_score(score)

            reason = self._build_reason(value, pivot_type, source_count, bucket["latest_seen"], score)
            recommended = self.RECOMMENDED_MODULES.get(pivot_type, ["comprehensive_sweep"])

            pivot = {
                "target": value,
                "target_type": pivot_type,
                "reason": reason,
                "confidence": round(score, 2),
                "priority": priority,
                "recommended_modules": recommended,
                "last_seen": bucket["latest_seen"].isoformat(),
                "source_count": source_count,
            }
            pivots.append(pivot)

            self.tracker.upsert_lead(
                investigation_id,
                target=value,
                target_type=pivot_type,
                reason=reason,
                priority=priority,
                suggested_modules=recommended,
                estimated_value="high" if score >= 0.7 else "medium",
                score=score,
                findings_count=len(bucket["confidence_scores"]),
            )

        pivots.sort(key=lambda p: (p["confidence"], p["source_count"]), reverse=True)
        return pivots[:max_pivots]

    def _normalize_finding_type(self, finding_type: str) -> Optional[str]:
        finding_type = finding_type.lower()
        if finding_type in {"domain", "subdomain", "ip", "email", "profile", "geolocation", "company"}:
            return finding_type
        if finding_type in {"url", "intel_reference"}:
            return "url"
        if finding_type in {"service_provider", "asn"}:
            return "company"
        if finding_type.startswith("dns"):
            return "domain"
        return None

    def _priority_from_score(self, score: float) -> str:
        if score >= 0.85:
            return "critical"
        if score >= 0.7:
            return "high"
        if score >= 0.55:
            return "medium"
        return "low"

    def _build_reason(
        self, value: str, pivot_type: str, sources: int, latest_seen: datetime, score: float
    ) -> str:
        freshness_hours = int(max(0.0, (_utcnow() - latest_seen).total_seconds() / 3600.0))
        return (
            f"{pivot_type.title()} {value} corroborated by {sources} module(s); "
            f"last seen {freshness_hours}h ago. Confidence score {score:.2f}."
        )


class AutonomousInvestigationEngine:
    """Closed-loop orchestration tying collectors, storage, and pivoting."""

    def __init__(
        self,
        tracker: Optional[InvestigationTracker] = None,
        collector: Optional[MultiINTCollector] = None,
        pivot_planner: Optional[EvidenceDrivenPivotPlanner] = None,
    ) -> None:
        self.tracker = tracker or InvestigationTracker()
        self.collector = collector or MultiINTCollector(self.tracker)
        self.pivot_planner = pivot_planner or EvidenceDrivenPivotPlanner(self.tracker)
        self.graph = get_default_graph()

    def ensure_investigation(self, investigation_id: str, name: str) -> None:
        self.tracker.create_investigation(investigation_id, name)
        self.graph.upsert_entity(
            "investigation", investigation_id, {"name": name, "created_at": _utcnow().isoformat()}
        )

    async def collect_and_plan(
        self,
        investigation_id: str,
        target: str,
        target_type: str,
        *,
        max_pivots: int = 5,
    ) -> Dict[str, Any]:
        collection = await self.collector.collect(investigation_id, target, target_type)
        pivots = self.pivot_planner.generate_pivots(investigation_id, max_pivots=max_pivots)
        return {"collection": collection, "pivots": pivots}

    async def suggest_pivots(
        self, investigation_id: str, *, max_pivots: int = 5
    ) -> List[Dict[str, Any]]:
        return self.pivot_planner.generate_pivots(investigation_id, max_pivots=max_pivots)

    async def execute_autonomous_investigation(
        self,
        initial_target: str,
        target_type: str,
        *,
        investigation_id: Optional[str] = None,
        max_depth: int = 3,
        max_pivots_per_level: int = 3,
    ) -> Dict[str, Any]:
        if investigation_id is None:
            investigation_id = f"auto_{int(time.time())}"
        self.ensure_investigation(investigation_id, f"Autonomous run for {initial_target}")

        queue: List[Tuple[str, str, int]] = [(initial_target, target_type, 0)]
        visited: set[str] = set()

        tree = {
            "investigation_id": investigation_id,
            "initial_target": initial_target,
            "target_type": target_type,
            "started_at": _utcnow().isoformat(),
            "levels": [],
        }

        while queue:
            target, ttype, depth = queue.pop(0)
            if depth >= max_depth or f"{ttype}:{target}" in visited:
                continue

            visited.add(f"{ttype}:{target}")
            level_result = await self.collect_and_plan(
                investigation_id, target, ttype, max_pivots=max_pivots_per_level
            )

            while len(tree["levels"]) <= depth:
                tree["levels"].append([])
            tree["levels"][depth].append(
                {
                    "target": target,
                    "target_type": ttype,
                    "collection": level_result["collection"],
                    "pivots": level_result["pivots"],
                }
            )

            for pivot in level_result["pivots"]:
                if pivot["priority"] in {"critical", "high"}:
                    queue.append((pivot["target"], pivot["target_type"], depth + 1))

        tree["completed_at"] = _utcnow().isoformat()
        tree["total_levels"] = len(tree["levels"])
        tree["total_targets"] = sum(len(level) for level in tree["levels"])
        tree["total_pivots"] = sum(len(node["pivots"]) for level in tree["levels"] for node in level)

        return tree

