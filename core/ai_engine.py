#!/usr/bin/env python3
"""
OSINT AI Engine
Advanced AI integration for automated analysis, threat assessment,
and intelligent reporting of OSINT investigations.
"""

import asyncio
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import openai
except ImportError:
    openai = None  # type: ignore

try:  # Optional provider
    from anthropic import Anthropic  # type: ignore
except Exception:  # pragma: no cover
    Anthropic = None  # type: ignore
from jinja2 import Template

from graph import get_default_graph

logger = logging.getLogger(__name__)


@dataclass
class AIAnalysisResult:
    """Result of AI analysis"""

    analysis_type: str
    summary: str
    findings: List[Dict[str, Any]]
    confidence_score: float
    recommendations: List[str]
    threat_level: str
    metadata: Dict[str, Any]
    generated_at: datetime


class OSINTAIEngine:
    """
    Advanced AI engine for OSINT analysis and reporting.
    Supports multiple AI providers and specialized OSINT prompts.
    Includes autopivoting for autonomous investigations.
    """

    def __init__(
        self,
        api_key: str,
        model_url: str = "https://api.openai.com/v1",
        model_name: str = "gpt-4",
        provider: str = "openai",
        enable_autopivot: bool = True,
        initialize_clients: bool = True,
    ):
        self.api_key = api_key
        self.model_url = model_url
        self.model_name = model_name
        self.provider = provider
        self.enable_autopivot = enable_autopivot
        self.client = None
        self._graph = get_default_graph()
        self._fallback_autopivot_engine = None

        # Initialize AI client when credentials/provider available
        if initialize_clients and self.api_key:
            self._init_ai_client()

        # Load analysis templates
        self.analysis_templates = self._load_analysis_templates()

        # OSINT-specific knowledge base
        self.osint_knowledge = self._load_osint_knowledge()

    def set_graph_adapter(self, graph_adapter) -> None:
        """Allow tests or callers to inject a specific graph adapter instance."""
        self._graph = graph_adapter

    def _init_ai_client(self):
        """Initialize AI client based on provider"""
        if not self.api_key:
            logger.info("AI client initialization skipped - no API key provided")
            self.client = None
            return
        if self.provider == "openai":
            if openai is None:
                raise ImportError("openai package is required for OpenAI provider")
            openai.api_key = self.api_key
            if self.model_url != "https://api.openai.com/v1":
                openai.api_base = self.model_url
            self.client = openai
        elif self.provider == "anthropic":
            if Anthropic is None:
                raise ImportError(
                    "anthropic provider requested but 'anthropic' package not installed"
                )
            self.client = Anthropic(api_key=self.api_key)
        elif self.provider == "perplexity":
            # Perplexity uses OpenAI-compatible API
            openai.api_key = self.api_key
            openai.api_base = self.model_url or "https://api.perplexity.ai"
            self.client = openai
        else:
            raise ValueError(f"Unsupported AI provider: {self.provider}")

    def _load_analysis_templates(self) -> Dict[str, str]:
        """Load analysis prompt templates"""
        return {
            "summary": """
            You are an expert OSINT analyst. Analyze the following investigation data and provide a comprehensive summary.
            
            Investigation: {investigation_name}
            Type: {investigation_type}
            Targets: {targets}
            
            Data collected:
            {investigation_data}
            
            Provide a structured analysis including:
            1. Executive Summary
            2. Key Findings
            3. Risk Assessment
            4. Notable Patterns
            5. Data Quality Assessment
            
            Format your response as structured JSON with clear sections.
            """,
            "threat_assessment": """
            You are a cybersecurity threat analyst specializing in OSINT. Assess the threat level based on the investigation data.
            
            Investigation Data:
            {investigation_data}
            
            Analyze for:
            1. Potential security threats
            2. Attack vectors
            3. Indicators of compromise (IOCs)
            4. Threat actor attribution
            5. Risk level (Low/Medium/High/Critical)
            
            Provide specific threat indicators and recommended mitigations.
            """,
            "recommendations": """
            As an OSINT expert, provide actionable recommendations based on the investigation findings.
            
            Investigation Results:
            {investigation_data}
            
            Provide recommendations for:
            1. Further investigation areas
            2. Security improvements
            3. Monitoring strategies
            4. Risk mitigation
            5. Additional data sources to explore
            
            Prioritize recommendations by impact and feasibility.
            """,
            "report": """
            Generate a professional OSINT investigation report based on the collected data.
            
            Investigation: {investigation_name}
            Duration: {investigation_duration}
            Analyst: {analyst_name}
            
            Data:
            {investigation_data}
            
            Structure the report with:
            1. Executive Summary
            2. Investigation Scope and Methodology
            3. Findings and Analysis
            4. Threat Assessment
            5. Recommendations
            6. Conclusion
            7. Appendices (technical details)
            
            Write in professional, clear language suitable for both technical and non-technical audiences.
            """,
        }

    def _load_osint_knowledge(self) -> Dict[str, Any]:
        """Load OSINT-specific knowledge base"""
        return {
            "threat_indicators": [
                "suspicious_domains",
                "malicious_ips",
                "phishing_patterns",
                "data_breaches",
                "leaked_credentials",
                "dark_web_mentions",
            ],
            "data_quality_checks": [
                "source_reliability",
                "data_freshness",
                "cross_validation",
                "false_positive_rate",
                "completeness_score",
            ],
            "investigation_types": {
                "domain": ["whois", "dns", "subdomains", "certificates", "reputation"],
                "ip": ["geolocation", "ownership", "services", "reputation", "history"],
                "email": ["validation", "breaches", "domains", "social_media"],
                "phone": ["carrier", "location", "validation", "social_media"],
                "company": ["registration", "contacts", "domains", "social_presence"],
                "person": ["social_media", "email", "phone", "employment", "breaches"],
            },
        }

    async def analyze_investigation(
        self,
        investigation_data: Dict[str, Any],
        analysis_type: str,
        context: Optional[str] = None,
        include_raw_data: bool = False,
    ) -> AIAnalysisResult:
        """
        Perform AI analysis of investigation data.

        Args:
            investigation_data: Complete investigation data
            analysis_type: Type of analysis (summary, threat_assessment, etc.)
            context: Additional context for analysis
            include_raw_data: Whether to include raw data in response
        """
        try:
            # Prepare data for analysis
            processed_data = self._preprocess_investigation_data(
                investigation_data, include_raw_data
            )

            # Select appropriate template
            template_text = self.analysis_templates.get(analysis_type)
            if not template_text:
                raise ValueError(f"Unknown analysis type: {analysis_type}")

            # Render prompt template
            template = Template(template_text)
            prompt = template.render(
                investigation_name=investigation_data.get("name", "Unknown"),
                investigation_type=investigation_data.get("type", "Unknown"),
                targets=", ".join(investigation_data.get("targets", [])),
                investigation_data=json.dumps(processed_data, indent=2),
                investigation_duration=self._calculate_duration(investigation_data),
                analyst_name="AI Assistant",
                context=context or "",
            )

            # Perform AI analysis
            ai_response = await self._call_ai_model(prompt, analysis_type)

            # Parse and structure response
            analysis_result = self._parse_ai_response(ai_response, analysis_type)

            # Enhance with OSINT-specific insights
            enhanced_result = await self._enhance_with_osint_insights(
                analysis_result, investigation_data
            )

            return enhanced_result

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            raise

    async def _call_ai_model(self, prompt: str, analysis_type: str) -> str:
        """Call the AI model with the prepared prompt"""
        try:
            if self.provider == "openai":
                response = await asyncio.to_thread(
                    self.client.chat.completions.create,  # type: ignore
                    model=self.model_name,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are an expert OSINT analyst with deep knowledge of "
                                "cybersecurity, threat intelligence, and open-source "
                                "investigation techniques."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    max_tokens=4000,
                )
                content = response.choices[0].message.content
                return content if content is not None else "No response generated"

            elif self.provider == "anthropic":
                response = await asyncio.to_thread(
                    self.client.messages.create,  # type: ignore
                    model=self.model_name,
                    max_tokens=4000,
                    temperature=0.3,
                    messages=[{"role": "user", "content": prompt}],
                )
                return response.content[0].text  # type: ignore

            elif self.provider == "perplexity":
                response = await asyncio.to_thread(
                    self.client.chat.completions.create,  # type: ignore
                    model=self.model_name,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are an expert OSINT analyst with deep knowledge of "
                                "cybersecurity, threat intelligence, and open-source "
                                "investigation techniques. You have access to real-time web search "
                                "and can provide up-to-date information."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    max_tokens=4000,
                )
                content = response.choices[0].message.content
                return content if content is not None else "No response generated"

        except Exception as e:
            logger.error(f"AI model call failed: {e}")
            raise

        # If no provider matched, return error message
        return f"Unsupported AI provider: {self.provider}"

    def _preprocess_investigation_data(
        self, investigation_data: Dict[str, Any], include_raw_data: bool = False
    ) -> Dict[str, Any]:
        """Preprocess investigation data for AI analysis"""
        processed = {
            "investigation_id": investigation_data.get("id"),
            "name": investigation_data.get("name"),
            "type": investigation_data.get("type"),
            "targets": investigation_data.get("targets", []),
            "status": investigation_data.get("status"),
            "created_at": investigation_data.get("created_at"),
            "findings_summary": self._summarize_findings(investigation_data),
            "data_sources": self._extract_data_sources(investigation_data),
            "metrics": self._calculate_metrics(investigation_data),
        }

        if include_raw_data:
            processed["raw_results"] = investigation_data.get("results", {})

        return processed

    def _summarize_findings(self, investigation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize key findings from investigation data"""
        results = investigation_data.get("results", {})

        summary: Dict[str, Any] = {
            "total_data_points": 0,
            "unique_domains": set(),
            "unique_ips": set(),
            "unique_emails": set(),
            "threat_indicators": [],
            "high_confidence_findings": [],
        }

        # Process results by task type
        for task_id, task_result in results.items():
            if not task_result or not isinstance(task_result, dict):
                continue

            task_data = task_result.get("data", {})
            summary["total_data_points"] += 1

            # Extract entities
            if "domains" in task_data:
                summary["unique_domains"].update(task_data["domains"])
            if "ips" in task_data:
                summary["unique_ips"].update(task_data["ips"])
            if "emails" in task_data:
                summary["unique_emails"].update(task_data["emails"])

            # Identify threat indicators
            if task_result.get("threat_score", 0) > 0.7:
                summary["threat_indicators"].append(
                    {
                        "task_id": task_id,
                        "threat_score": task_result.get("threat_score"),
                        "description": task_result.get("description"),
                    }
                )

            # High confidence findings
            if task_result.get("confidence", 0) > 0.8:
                summary["high_confidence_findings"].append(
                    {
                        "task_id": task_id,
                        "confidence": task_result.get("confidence"),
                        "finding": task_result.get("summary"),
                    }
                )

        # Convert sets to lists for JSON serialization
        summary["unique_domains"] = list(summary["unique_domains"])
        summary["unique_ips"] = list(summary["unique_ips"])
        summary["unique_emails"] = list(summary["unique_emails"])

        return summary

    def _extract_data_sources(self, investigation_data: Dict[str, Any]) -> List[str]:
        """Extract list of data sources used in investigation"""
        sources = set()
        results = investigation_data.get("results", {})

        for task_result in results.values():
            if isinstance(task_result, dict):
                task_source = task_result.get("source")
                if task_source:
                    sources.add(task_source)

        return list(sources)

    def _calculate_metrics(self, investigation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate investigation metrics"""
        results = investigation_data.get("results", {})

        metrics = {
            "total_tasks": len(results),
            "completed_tasks": 0,
            "failed_tasks": 0,
            "average_confidence": 0.0,
            "average_threat_score": 0.0,
            "data_coverage": 0.0,
        }

        confidences = []
        threat_scores = []

        for task_result in results.values():
            if isinstance(task_result, dict):
                status = task_result.get("status", "unknown")
                if status == "completed":
                    metrics["completed_tasks"] += 1
                elif status == "failed":
                    metrics["failed_tasks"] += 1

                confidence = task_result.get("confidence")
                if confidence is not None:
                    confidences.append(confidence)

                threat_score = task_result.get("threat_score")
                if threat_score is not None:
                    threat_scores.append(threat_score)

        if confidences:
            metrics["average_confidence"] = sum(confidences) / len(confidences)
        if threat_scores:
            metrics["average_threat_score"] = sum(threat_scores) / len(threat_scores)

        if metrics["total_tasks"] > 0:
            metrics["data_coverage"] = (
                metrics["completed_tasks"] / metrics["total_tasks"]
            )

        return metrics

    def _calculate_duration(self, investigation_data: Dict[str, Any]) -> str:
        """Calculate investigation duration"""
        created_at = investigation_data.get("created_at")
        completed_at = investigation_data.get("completed_at")

        if not created_at:
            return "Unknown"

        try:
            start_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))

            if completed_at:
                end_time = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
            else:
                end_time = datetime.now()

            duration = end_time - start_time

            if duration.days > 0:
                return f"{duration.days} days, {duration.seconds // 3600} hours"
            elif duration.seconds > 3600:
                return f"{duration.seconds // 3600} hours, {(duration.seconds % 3600) // 60} minutes"
            else:
                return f"{duration.seconds // 60} minutes"

        except Exception:
            return "Unknown"

    def _parse_ai_response(
        self, ai_response: str, analysis_type: str
    ) -> AIAnalysisResult:
        """Parse AI response into structured result"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r"\{.*\}", ai_response, re.DOTALL)
            if json_match:
                structured_data = json.loads(json_match.group())
            else:
                # Fallback to text parsing
                structured_data = self._parse_text_response(ai_response, analysis_type)

            return AIAnalysisResult(
                analysis_type=analysis_type,
                summary=structured_data.get("summary", ai_response[:500]),
                findings=structured_data.get("findings", []),
                confidence_score=structured_data.get("confidence_score", 0.8),
                recommendations=structured_data.get("recommendations", []),
                threat_level=structured_data.get("threat_level", "Unknown"),
                metadata=structured_data.get("metadata", {}),
                generated_at=datetime.now(),
            )

        except Exception as e:
            logger.warning(f"Failed to parse AI response as JSON: {e}")

            # Fallback to basic text response
            return AIAnalysisResult(
                analysis_type=analysis_type,
                summary=ai_response,
                findings=[],
                confidence_score=0.7,
                recommendations=[],
                threat_level="Unknown",
                metadata={"raw_response": ai_response},
                generated_at=datetime.now(),
            )

    def _parse_text_response(self, response: str, analysis_type: str) -> Dict[str, Any]:
        """Parse text response into structured data"""
        structured = {
            "summary": "",
            "findings": [],
            "recommendations": [],
            "threat_level": "Unknown",
            "confidence_score": 0.7,
        }

        lines = response.split("\n")
        current_section = None
        current_content: List[str] = []

        for line in lines:
            line = line.strip()

            # Detect section headers
            if any(keyword in line.lower() for keyword in ["summary", "executive"]):
                if current_section and current_content:
                    self._add_section_content(
                        structured, current_section, current_content
                    )
                current_section = "summary"
                current_content = []
            elif any(keyword in line.lower() for keyword in ["findings", "results"]):
                if current_section and current_content:
                    self._add_section_content(
                        structured, current_section, current_content
                    )
                current_section = "findings"
                current_content = []
            elif any(
                keyword in line.lower() for keyword in ["recommendations", "next steps"]
            ):
                if current_section and current_content:
                    self._add_section_content(
                        structured, current_section, current_content
                    )
                current_section = "recommendations"
                current_content = []
            elif line:
                current_content.append(line)

        # Add final section
        if current_section and current_content:
            self._add_section_content(structured, current_section, current_content)

        return structured

    def _add_section_content(
        self, structured: Dict[str, Any], section: str, content: List[str]
    ):
        """Add parsed content to structured data"""
        content_text = "\n".join(content)

        if section == "summary":
            structured["summary"] = content_text
        elif section == "findings":
            # Split into individual findings
            findings = []
            for item in content:
                if item.startswith(("-", "•", "*", "1.", "2.", "3.")):
                    findings.append({"description": item.strip("- •*123456789.")})
            structured["findings"] = findings
        elif section == "recommendations":
            # Split into individual recommendations
            recommendations = []
            for item in content:
                if item.startswith(("-", "•", "*", "1.", "2.", "3.")):
                    recommendations.append(item.strip("- •*123456789."))
            structured["recommendations"] = recommendations

    async def _enhance_with_osint_insights(
        self, analysis_result: AIAnalysisResult, investigation_data: Dict[str, Any]
    ) -> AIAnalysisResult:
        """Enhance AI analysis with OSINT-specific insights"""
        try:
            # Add OSINT-specific threat scoring
            osint_threat_score = self._calculate_osint_threat_score(investigation_data)

            # Add data quality assessment
            data_quality = self._assess_data_quality(investigation_data)

            # Enhance metadata
            enhanced_metadata = {
                **analysis_result.metadata,
                "osint_threat_score": osint_threat_score,
                "data_quality": data_quality,
                "enhancement_version": "1.0",
            }

            # Update analysis result
            analysis_result.metadata = enhanced_metadata

            # Adjust confidence based on data quality
            quality_factor = data_quality.get("overall_score", 0.8)
            analysis_result.confidence_score *= quality_factor

            return analysis_result

        except Exception as e:
            logger.warning(f"Failed to enhance with OSINT insights: {e}")
            return analysis_result

    def _calculate_osint_threat_score(
        self, investigation_data: Dict[str, Any]
    ) -> float:
        """Calculate OSINT-specific threat score"""
        score = 0.0
        factors = 0

        results = investigation_data.get("results", {})

        for task_result in results.values():
            if isinstance(task_result, dict):
                # Check for threat indicators
                threat_score = task_result.get("threat_score", 0)
                if threat_score > 0:
                    score += threat_score
                    factors += 1

                # Check for suspicious patterns
                data = task_result.get("data", {})
                if self._contains_suspicious_patterns(data):
                    score += 0.3
                    factors += 1

        return score / factors if factors > 0 else 0.0

    def _contains_suspicious_patterns(self, data: Dict[str, Any]) -> bool:
        """Check for suspicious patterns in OSINT data"""
        suspicious_patterns = [
            r"\.tk$",
            r"\.ml$",
            r"\.ga$",  # Suspicious TLDs
            r"temp.*mail",
            r"10minute.*mail",  # Temporary email patterns
            r"vpn|proxy|tor",  # Anonymization services
        ]

        data_str = json.dumps(data).lower()

        for pattern in suspicious_patterns:
            if re.search(pattern, data_str):
                return True

        return False

    def _assess_data_quality(
        self, investigation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess quality of investigation data"""
        results = investigation_data.get("results", {})

        quality_assessment = {
            "completeness": 0.0,
            "reliability": 0.0,
            "freshness": 0.0,
            "coverage": 0.0,
            "overall_score": 0.0,
        }

        if not results:
            return quality_assessment

        total_tasks = len(results)
        completed_tasks = 0
        reliable_sources = 0
        fresh_data = 0

        for task_result in results.values():
            if isinstance(task_result, dict):
                # Completeness
                if task_result.get("status") == "completed":
                    completed_tasks += 1

                # Reliability (based on source reputation)
                source = task_result.get("source", "").lower()
                if any(
                    trusted in source
                    for trusted in ["official", "government", "verified"]
                ):
                    reliable_sources += 1

                # Freshness (data age)
                timestamp = task_result.get("timestamp")
                if timestamp and self._is_fresh_data(timestamp):
                    fresh_data += 1

        # Calculate scores
        quality_assessment["completeness"] = completed_tasks / total_tasks
        quality_assessment["reliability"] = reliable_sources / total_tasks
        quality_assessment["freshness"] = fresh_data / total_tasks
        quality_assessment["coverage"] = min(
            1.0, total_tasks / 10
        )  # Assume 10 is ideal

        # Overall score (weighted average)
        quality_assessment["overall_score"] = (
            quality_assessment["completeness"] * 0.4
            + quality_assessment["reliability"] * 0.3
            + quality_assessment["freshness"] * 0.2
            + quality_assessment["coverage"] * 0.1
        )

        return quality_assessment

    def _is_fresh_data(self, timestamp: str, max_age_hours: int = 24) -> bool:
        """Check if data is considered fresh"""
        try:
            data_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            age = datetime.now() - data_time
            return age.total_seconds() < (max_age_hours * 3600)
        except Exception:
            return False

    async def chat_with_investigation(
        self,
        investigation_id: str,
        user_message: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        """Interactive chat about investigation data"""
        try:
            # This would integrate with your investigation manager
            # to get current investigation data and maintain conversation context

            chat_prompt = f"""
            You are an OSINT analyst assistant. The user is asking about investigation {investigation_id}.
            
            User question: {user_message}
            
            Previous conversation:
            {json.dumps(conversation_history or [], indent=2)}
            
            Provide helpful, accurate responses based on the investigation data.
            """

            response = await self._call_ai_model(chat_prompt, "chat")
            return response

        except Exception as e:
            logger.error(f"Chat interaction failed: {e}")
            return "I'm sorry, I encountered an error processing your request."

    async def suggest_autopivots(
        self,
        investigation_data: Dict[str, Any],
        max_pivots: int = 5,
        store: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """
        Suggest intelligent pivot points for autonomous investigation expansion.

        Args:
            investigation_data: Current investigation data
            max_pivots: Maximum number of pivot suggestions

        Returns:
            List of pivot suggestions with confidence scores
        """
        if not self.enable_autopivot:
            logger.warning("Autopivoting is disabled")
            return []

        investigation_id = investigation_data.get("id")
        if not investigation_id:
            logger.warning(
                "Investigation data missing identifier for autopivot scoring; "
                "falling back to heuristic autopivot engine"
            )
            fallback_engine = self._get_fallback_autopivot_engine()
            if fallback_engine is None:
                return []
            try:
                return await fallback_engine.suggest_autopivots(
                    investigation_data, max_pivots
                )
            except Exception as fallback_error:
                logger.error(
                    "Fallback autopivot engine failed: %s", fallback_error
                )
                return []

        try:
            if not self._should_rescore_pivots(investigation_data):
                stored = investigation_data.get("latest_pivots", [])
                return stored[:max_pivots]

            findings = []
            try:
                from core.investigation_tracker import get_investigation_tracker

                tracker = get_investigation_tracker()
                findings = tracker.get_all_findings(investigation_id)
            except Exception as tracker_error:
                logger.debug(f"Investigation tracker unavailable: {tracker_error}")

            graph_entities, graph_degrees = self._collect_graph_context(investigation_id)
            pivots, pivot_scores = self._score_pivots(
                investigation_id,
                findings,
                graph_entities,
                graph_degrees,
                investigation_data.get("targets", []),
            )

            if store is not None and hasattr(store, "update_pivot_scores"):
                try:
                    await store.update_pivot_scores(investigation_id, pivot_scores, pivots)
                except Exception as store_error:
                    logger.error(f"Failed to persist pivot scores: {store_error}")

            return pivots[:max_pivots]

        except Exception as e:
            logger.error(f"Autopivot suggestion failed: {e}")
            return []

    def _get_fallback_autopivot_engine(self):
        if self._fallback_autopivot_engine is False:
            return None
        if self._fallback_autopivot_engine is None:
            try:
                from core.autopivot_fallback import (
                    DeterministicAutopivotEngine,
                )

                self._fallback_autopivot_engine = DeterministicAutopivotEngine()
            except Exception as exc:  # pragma: no cover - defensive guard
                logger.error(
                    "Unable to initialize fallback autopivot engine: %s", exc
                )
                self._fallback_autopivot_engine = False
        return self._fallback_autopivot_engine or None

    def _should_rescore_pivots(self, investigation_data: Dict[str, Any]) -> bool:
        if investigation_data.get("pending_pivot_rescore"):
            return True
        if not investigation_data.get("latest_pivots"):
            return True
        if not investigation_data.get("pivot_scores"):
            return True
        last_evidence = investigation_data.get("last_evidence_at")
        scored_info = investigation_data.get("pivot_scores", {})
        scored_at = scored_info.get("_last_scored_at") if isinstance(scored_info, dict) else None
        if last_evidence and scored_at:
            try:
                evidence_dt = datetime.fromisoformat(str(last_evidence))
                scored_dt = datetime.fromisoformat(str(scored_at))
                if scored_dt < evidence_dt:
                    return True
            except Exception:
                return True
        return False

    def _collect_graph_context(
        self, investigation_id: str
    ) -> Tuple[Dict[Tuple[str, str], Dict[str, Any]], Dict[Tuple[str, str], int]]:
        snapshot = self._graph.export_snapshot()
        entities: Dict[Tuple[str, str], Dict[str, Any]] = {}
        degrees: Dict[Tuple[str, str], int] = defaultdict(int)
        for ent in snapshot.get("entities", []):
            props = ent.get("properties", {})
            inv_ids = props.get("investigation_ids")
            if isinstance(inv_ids, (list, tuple, set)):
                if investigation_id not in {str(i) for i in inv_ids}:
                    continue
            elif props.get("investigation_id") != investigation_id:
                continue
            key = (ent.get("type"), ent.get("key"))
            if None in key:
                continue
            entities[key] = ent
        for edge in snapshot.get("edges", []):
            for endpoint in (edge.get("source"), edge.get("target")):
                if not endpoint:
                    continue
                endpoint_key = tuple(endpoint)
                if endpoint_key in entities:
                    degrees[endpoint_key] += 1
        return entities, degrees

    def _score_pivots(
        self,
        investigation_id: str,
        findings: List[Any],
        graph_entities: Dict[Tuple[str, str], Dict[str, Any]],
        graph_degrees: Dict[Tuple[str, str], int],
        initial_targets: List[str],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        from capabilities import REGISTRY

        recommended_modules = {
            "domain": ["dns_basic", "whois_lookup", "ssl_cert_fetch"],
            "ip": ["dns_basic"],
            "email": ["passive_search"],
            "person": ["passive_search"],
            "company": ["passive_search"],
        }

        def module_list(ftype: str) -> List[str]:
            mods = recommended_modules.get(ftype, ["passive_search"])
            filtered = [m for m in mods if m in REGISTRY]
            return filtered or mods

        aggregated: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for finding in findings:
            key = (finding.finding_type, finding.value)
            if key not in aggregated:
                aggregated[key] = {
                    "score": 0.0,
                    "finding_ids": [],
                    "source_modules": set(),
                    "confidence": [],
                    "graph_degree": graph_degrees.get(key, 0),
                }
            entry = aggregated[key]
            entry["finding_ids"].append(finding.id)
            entry["source_modules"].add(finding.source_module)
            entry["confidence"].append(float(getattr(finding, "confidence", 0.6) if getattr(finding, "confidence", None) is not None else 0.6))
            entry["graph_degree"] = max(entry["graph_degree"], graph_degrees.get(key, 0))

        # include graph entities not already captured by findings
        for key, entity in graph_entities.items():
            if key not in aggregated:
                aggregated[key] = {
                    "score": 0.0,
                    "finding_ids": [],
                    "source_modules": set([entity["properties"].get("source_module", "graph")]),
                    "confidence": [float(entity["properties"].get("confidence", 0.5) or 0.5)],
                    "graph_degree": graph_degrees.get(key, 0),
                }

        pivots: List[Dict[str, Any]] = []
        pivot_scores: Dict[str, Any] = {}
        initial_targets_set = {t.lower() for t in initial_targets}

        for (ftype, value), data in aggregated.items():
            if not value:
                continue
            base = {
                "domain": 0.55,
                "ip": 0.6,
                "email": 0.5,
                "person": 0.5,
                "company": 0.5,
            }.get(ftype, 0.45)
            avg_conf = sum(data["confidence"]) / max(len(data["confidence"]), 1)
            graph_boost = min(0.2, 0.05 * data["graph_degree"])
            score = max(0.1, min(1.0, base + 0.4 * avg_conf + graph_boost))
            reason_parts = []
            if data["finding_ids"]:
                modules_txt = ", ".join(sorted(data["source_modules"])) or "unknown modules"
                reason_parts.append(
                    f"Observed by {modules_txt} with mean confidence {avg_conf:.2f}."
                )
            else:
                reason_parts.append("Derived from investigation graph relationships.")
            if data["graph_degree"]:
                reason_parts.append(
                    f"Connected to {data['graph_degree']} related entities in the knowledge graph."
                )
            if value.lower() in initial_targets_set:
                reason_parts.append("Matches an existing investigation target, consider deeper enrichment.")
            reason = " ".join(reason_parts)
            modules = module_list(ftype)
            pivot_entry = {
                "target": value,
                "target_type": ftype,
                "reason": reason,
                "confidence": round(score, 3),
                "priority": self._score_to_priority(score),
                "recommended_modules": modules,
                "supporting_findings": len(data["finding_ids"]),
            }
            pivots.append(pivot_entry)
            pivot_scores[value] = {
                "score": round(score, 3),
                "target_type": ftype,
                "finding_ids": data["finding_ids"],
                "source_modules": sorted(data["source_modules"]),
                "graph_degree": data["graph_degree"],
            }

        pivots.sort(key=lambda item: item["confidence"], reverse=True)
        return pivots, pivot_scores

    @staticmethod
    def _score_to_priority(score: float) -> str:
        if score >= 0.75:
            return "high"
        if score >= 0.5:
            return "medium"
        return "low"

    def _extract_pivots_from_text(
        self, response: str, max_pivots: int
    ) -> List[Dict[str, Any]]:
        """Extract pivot suggestions from plain text response"""
        pivots = []

        # Simple pattern matching for entities
        import re

        # Find domains
        domains = re.findall(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", response
        )
        for domain in domains[:max_pivots]:
            pivots.append(
                {
                    "target": domain,
                    "target_type": "domain",
                    "reason": "Related domain identified in analysis",
                    "confidence": 0.7,
                    "priority": "medium",
                    "recommended_modules": ["domain_recon", "dns_intel"],
                }
            )

        # Find email addresses
        emails = re.findall(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", response
        )
        for email in emails[: max_pivots - len(pivots)]:
            pivots.append(
                {
                    "target": email,
                    "target_type": "email",
                    "reason": "Related email address identified",
                    "confidence": 0.7,
                    "priority": "medium",
                    "recommended_modules": ["email_intel", "breach_search"],
                }
            )

        return pivots[:max_pivots]

    async def execute_autonomous_investigation(
        self,
        initial_target: str,
        target_type: str,
        max_depth: int = 3,
        max_pivots_per_level: int = 3,
    ) -> Dict[str, Any]:
        """
        Execute fully autonomous investigation with automatic pivoting.

        Args:
            initial_target: Starting investigation target
            target_type: Type of initial target
            max_depth: Maximum pivot depth
            max_pivots_per_level: Maximum pivots to explore per level

        Returns:
            Complete investigation results with all pivot paths
        """
        if not self.enable_autopivot:
            raise ValueError(
                "Autopivoting must be enabled for autonomous investigations"
            )

        logger.info(f"Starting autonomous investigation: {initial_target}")

        investigation_tree = {
            "initial_target": initial_target,
            "target_type": target_type,
            "started_at": datetime.now().isoformat(),
            "levels": [],
            "total_targets_investigated": 0,
            "total_pivots": 0,
        }

        current_targets = [(initial_target, target_type, 0)]  # (target, type, depth)
        investigated = set()

        while (
            current_targets and investigation_tree["total_targets_investigated"] < 100
        ):
            target, ttype, depth = current_targets.pop(0)

            if depth >= max_depth or target in investigated:
                continue

            investigated.add(target)
            investigation_tree["total_targets_investigated"] += 1

            logger.info(f"Investigating: {target} (depth: {depth})")

            # Create investigation for this target
            target_investigation = {
                "target": target,
                "target_type": ttype,
                "depth": depth,
                "results": {},
                "pivots": [],
            }

            # Get pivot suggestions
            pivots = await self.suggest_autopivots(
                investigation_data={
                    "name": f"Autonomous investigation of {target}",
                    "targets": [target],
                    "results": target_investigation.get("results", {}),
                },
                max_pivots=max_pivots_per_level,
            )

            target_investigation["pivots"] = pivots
            investigation_tree["total_pivots"] += len(pivots)

            # Add high-priority pivots to investigation queue
            for pivot in pivots:
                if pivot.get("priority") in ["high", "medium"]:
                    current_targets.append(
                        (pivot["target"], pivot["target_type"], depth + 1)
                    )

            # Add to appropriate level
            while len(investigation_tree["levels"]) <= depth:
                investigation_tree["levels"].append([])

            investigation_tree["levels"][depth].append(target_investigation)

        investigation_tree["completed_at"] = datetime.now().isoformat()

        logger.info(
            f"Autonomous investigation complete: {investigation_tree['total_targets_investigated']} targets, "
            f"{investigation_tree['total_pivots']} pivots identified"
        )

        return investigation_tree
