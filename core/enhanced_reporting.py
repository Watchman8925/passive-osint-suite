#!/usr/bin/env python3
"""
Enhanced Reporting Engine
Provides detailed, user-friendly investigation reports with clear explanations
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class EnhancedReportGenerator:
    """
    Generate comprehensive, user-friendly investigation reports.
    Breaks down findings into clear sections with explanations.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_user_friendly_report(
        self,
        investigation_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        leads: List[Dict[str, Any]],
        analysis: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive, user-friendly investigation report.

        Report structure:
        1. Executive Summary - What we found in plain English
        2. What We Know - Confirmed facts and data
        3. What We Think - Analysis and patterns
        4. What We Can Find - Potential leads and next steps
        5. Why It Matters - Significance of findings
        """

        report = {
            "report_id": f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "investigation_id": investigation_data.get("id", "unknown"),
            "investigation_name": investigation_data.get(
                "name", "Unnamed Investigation"
            ),
            # Section 1: Executive Summary
            "executive_summary": self._generate_executive_summary(
                investigation_data, findings, leads
            ),
            # Section 2: What We Know (Facts)
            "what_we_know": self._categorize_known_facts(findings),
            # Section 3: What We Think (Analysis)
            "what_we_think": self._generate_analysis_section(findings, analysis),
            # Section 4: What We Can Find (Leads)
            "what_we_can_find": self._format_investigation_leads(leads),
            # Section 5: Why It Matters (Significance)
            "why_it_matters": self._explain_significance(investigation_data, findings),
            # Additional sections
            "timeline": self._build_timeline(findings),
            "risk_assessment": self._assess_risks(findings),
            "recommendations": self._generate_recommendations(findings, leads),
            "statistics": self._calculate_statistics(findings, leads),
        }

        return report

    def _generate_executive_summary(
        self,
        investigation_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        leads: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate executive summary in plain English"""

        targets = investigation_data.get("targets", [])

        # Count findings by type
        findings_by_type = defaultdict(int)
        for finding in findings:
            findings_by_type[finding.get("finding_type", "unknown")] += 1

        # Determine key discovery
        key_discovery = "No significant discoveries yet"
        if findings:
            most_common = max(findings_by_type.items(), key=lambda x: x[1])
            key_discovery = f"Found {most_common[1]} {most_common[0]} entries"

        summary_text = f"""
Investigation of {", ".join(targets[:3])} {"and others" if len(targets) > 3 else ""}.

We collected {len(findings)} total data points across {len(findings_by_type)} different categories.
Key discovery: {key_discovery}.

Status: {len([lead for lead in leads if lead.get("status") == "pending"])} leads pending investigation, 
{len([lead for lead in leads if lead.get("status") == "completed"])} already explored.
        """.strip()

        return {
            "text": summary_text,
            "total_findings": len(findings),
            "total_leads": len(leads),
            "key_categories": list(findings_by_type.keys())[:5],
            "progress_percentage": self._calculate_progress(findings, leads),
        }

    def _categorize_known_facts(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Categorize findings into 'What We Know' sections"""

        categories = {
            "infrastructure": {
                "title": "Infrastructure & Technical Assets",
                "description": "Domains, IPs, and technical infrastructure we identified",
                "items": [],
            },
            "identities": {
                "title": "People & Identities",
                "description": "Email addresses, usernames, and personal identifiers",
                "items": [],
            },
            "exposures": {
                "title": "Security Exposures",
                "description": "Breaches, vulnerabilities, and security issues found",
                "items": [],
            },
            "connections": {
                "title": "Relationships & Connections",
                "description": "Links between entities and associated accounts",
                "items": [],
            },
            "other": {
                "title": "Other Findings",
                "description": "Additional information discovered",
                "items": [],
            },
        }

        # Categorize each finding
        for finding in findings:
            finding_type = finding.get("finding_type", "unknown")
            value = finding.get("value", "N/A")
            source = finding.get("source_module", "unknown")
            confidence = finding.get("confidence", 0.0)

            item = {
                "value": value,
                "source": source,
                "confidence": confidence,
                "explanation": self._explain_finding_value(finding_type, value),
                "verified": confidence > 0.8,
            }

            # Route to appropriate category
            if finding_type in ["domain", "ip", "subdomain", "server"]:
                categories["infrastructure"]["items"].append(item)
            elif finding_type in ["email", "username", "phone", "name"]:
                categories["identities"]["items"].append(item)
            elif finding_type in ["breach", "vulnerability", "exposure", "leak"]:
                categories["exposures"]["items"].append(item)
            elif finding_type in ["social_profile", "account", "association"]:
                categories["connections"]["items"].append(item)
            else:
                categories["other"]["items"].append(item)

        # Remove empty categories
        return {k: v for k, v in categories.items() if v["items"]}

    def _generate_analysis_section(
        self, findings: List[Dict[str, Any]], analysis: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate 'What We Think' analysis section"""

        patterns = self._identify_patterns(findings)
        connections = self._identify_connections(findings)
        anomalies = self._identify_anomalies(findings)

        analysis_section = {
            "patterns_detected": {
                "title": "Patterns We Detected",
                "description": "Recurring themes and patterns in the data",
                "items": patterns,
            },
            "connections": {
                "title": "Connections We See",
                "description": "How different findings relate to each other",
                "items": connections,
            },
            "anomalies": {
                "title": "Unusual Findings",
                "description": "Things that stand out or seem unexpected",
                "items": anomalies,
            },
        }

        # Add AI analysis if available
        if analysis:
            analysis_section["ai_insights"] = {
                "title": "AI Analysis",
                "description": "Insights from automated analysis",
                "summary": analysis.get("summary", ""),
                "confidence": analysis.get("confidence", 0.0),
            }

        return analysis_section

    def _format_investigation_leads(
        self, leads: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Format leads into 'What We Can Find' section"""

        # Group by priority
        critical_leads = []
        high_priority_leads = []
        other_leads = []

        for lead in leads:
            if lead.get("status") != "completed":  # Only pending leads
                lead_info = {
                    "target": lead.get("target", "Unknown"),
                    "type": lead.get("target_type", "unknown"),
                    "reason": lead.get("reason", "No reason provided"),
                    "why_it_matters": self._explain_lead_importance(lead),
                    "suggested_modules": lead.get("suggested_modules", []),
                    "estimated_time": self._estimate_investigation_time(lead),
                    "potential_findings": self._predict_potential_findings(lead),
                }

                priority = lead.get("priority", "medium")
                if priority == "critical":
                    critical_leads.append(lead_info)
                elif priority == "high":
                    high_priority_leads.append(lead_info)
                else:
                    other_leads.append(lead_info)

        return {
            "critical": {
                "title": "Critical Leads - Investigate Immediately",
                "description": "These leads could reveal important information quickly",
                "count": len(critical_leads),
                "leads": critical_leads,
            },
            "high_priority": {
                "title": "High Priority Leads - Investigate Soon",
                "description": "These leads are likely to provide valuable insights",
                "count": len(high_priority_leads),
                "leads": high_priority_leads,
            },
            "other": {
                "title": "Additional Leads - Investigate When Time Permits",
                "description": "These leads may provide supplementary information",
                "count": len(other_leads),
                "leads": other_leads[:10],  # Limit to top 10
            },
        }

    def _explain_significance(
        self, investigation_data: Dict[str, Any], findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Explain why findings matter to the investigation"""

        significance = {
            "overall": self._explain_overall_significance(investigation_data, findings),
            "key_impacts": [],
            "potential_uses": [],
        }

        # Identify key impacts
        if any(f.get("finding_type") == "breach" for f in findings):
            significance["key_impacts"].append(
                {
                    "category": "Security Risk",
                    "explanation": "Breach exposure means credentials may be compromised, enabling unauthorized access",
                    "action_needed": "Reset passwords and enable two-factor authentication",
                }
            )

        if any(f.get("finding_type") == "subdomain" for f in findings):
            significance["key_impacts"].append(
                {
                    "category": "Attack Surface",
                    "explanation": "Each subdomain represents a potential entry point for attackers",
                    "action_needed": "Review subdomain security and decommission unused ones",
                }
            )

        if any(f.get("finding_type") == "email" for f in findings):
            significance["key_impacts"].append(
                {
                    "category": "Identity Intelligence",
                    "explanation": "Email addresses connect to accounts, social profiles, and other services",
                    "action_needed": "Map email addresses to associated accounts and services",
                }
            )

        # Potential uses of the intelligence
        significance["potential_uses"] = [
            "Security assessment and vulnerability identification",
            "Threat intelligence and risk evaluation",
            "Digital footprint mapping and privacy assessment",
            "Incident response and forensic investigation",
            "Compliance and regulatory requirements",
        ]

        return significance

    def _build_timeline(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build chronological timeline of discoveries"""

        timeline = []
        for finding in sorted(findings, key=lambda x: x.get("discovered_at", "")):
            timeline.append(
                {
                    "timestamp": finding.get("discovered_at", "Unknown"),
                    "event": f"Discovered {finding.get('finding_type', 'unknown')}: {finding.get('value', 'N/A')}",
                    "source": finding.get("source_module", "unknown"),
                    "significance": self._rate_significance(finding),
                }
            )

        return timeline[-20:]  # Last 20 events

    def _assess_risks(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess security and privacy risks"""

        risk_score = 0
        risk_factors = []

        # Check for breach exposure
        breach_count = sum(1 for f in findings if f.get("finding_type") == "breach")
        if breach_count > 0:
            risk_score += breach_count * 2
            risk_factors.append(
                f"Found {breach_count} breach exposure(s) - credentials may be compromised"
            )

        # Check for exposed services
        exposed_services = [f for f in findings if "port" in f.get("metadata", {})]
        if exposed_services:
            risk_score += len(exposed_services)
            risk_factors.append(f"{len(exposed_services)} exposed services detected")

        # Check for admin interfaces
        admin_findings = [
            f for f in findings if "admin" in str(f.get("value", "")).lower()
        ]
        if admin_findings:
            risk_score += len(admin_findings) * 3
            risk_factors.append(
                f"{len(admin_findings)} administrative interfaces found"
            )

        # Determine risk level
        if risk_score >= 10:
            level = "High"
            color = "red"
        elif risk_score >= 5:
            level = "Medium"
            color = "yellow"
        else:
            level = "Low"
            color = "green"

        return {
            "level": level,
            "score": risk_score,
            "color": color,
            "factors": risk_factors,
            "recommendation": self._get_risk_recommendation(level),
        }

    def _generate_recommendations(
        self, findings: List[Dict[str, Any]], leads: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate actionable recommendations"""

        recommendations = []

        # Based on findings
        if any(f.get("finding_type") == "breach" for f in findings):
            recommendations.append(
                {
                    "priority": "critical",
                    "action": "Review and update all exposed credentials immediately",
                    "reason": "Breach data was discovered",
                    "estimated_time": "30-60 minutes",
                }
            )

        # Based on pending leads
        high_value_leads = [
            lead
            for lead in leads
            if lead.get("estimated_value") == "high" and lead.get("status") == "pending"
        ]
        if high_value_leads:
            recommendations.append(
                {
                    "priority": "high",
                    "action": f"Investigate {len(high_value_leads)} high-value leads",
                    "reason": "These leads likely contain important information",
                    "estimated_time": f"{len(high_value_leads) * 10}-{len(high_value_leads) * 20} minutes",
                }
            )

        # General recommendations
        recommendations.append(
            {
                "priority": "medium",
                "action": "Export and archive current findings",
                "reason": "Preserve investigation data for future reference",
                "estimated_time": "5 minutes",
            }
        )

        return recommendations

    def _calculate_statistics(
        self, findings: List[Dict[str, Any]], leads: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate investigation statistics"""

        findings_by_type = defaultdict(int)
        findings_by_source = defaultdict(int)

        for finding in findings:
            findings_by_type[finding.get("finding_type", "unknown")] += 1
            findings_by_source[finding.get("source_module", "unknown")] += 1

        return {
            "total_findings": len(findings),
            "total_leads": len(leads),
            "pending_leads": len(
                [lead for lead in leads if lead.get("status") == "pending"]
            ),
            "completed_leads": len(
                [lead for lead in leads if lead.get("status") == "completed"]
            ),
            "findings_by_type": dict(findings_by_type),
            "findings_by_source": dict(findings_by_source),
            "average_confidence": sum(f.get("confidence", 0) for f in findings)
            / len(findings)
            if findings
            else 0,
            "high_confidence_findings": len(
                [f for f in findings if f.get("confidence", 0) > 0.8]
            ),
        }

    # Helper methods

    def _explain_finding_value(self, finding_type: str, value: str) -> str:
        """Explain what a finding means"""
        explanations = {
            "email": "Email address that can be checked for breaches and linked accounts",
            "domain": "Website or service domain that can be further investigated",
            "ip": "Server IP address that can reveal hosting and services",
            "subdomain": "Additional web property that may host services",
            "breach": "Data leak containing potentially sensitive information",
            "username": "User identifier that may appear on multiple platforms",
        }
        return explanations.get(
            finding_type, "Data point discovered during investigation"
        )

    def _explain_lead_importance(self, lead: Dict[str, Any]) -> str:
        """Explain why a lead is important"""
        target_type = lead.get("target_type", "unknown")

        importance_map = {
            "email": "Email addresses often expose additional accounts and breach data",
            "domain": "Domains reveal organizational infrastructure and potential vulnerabilities",
            "ip": "IP addresses show hosting details and related services",
            "username": "Usernames frequently reused across platforms, enabling tracking",
        }

        return importance_map.get(
            target_type, "May provide valuable investigation intelligence"
        )

    def _estimate_investigation_time(self, lead: Dict[str, Any]) -> str:
        """Estimate time to investigate a lead"""
        modules = lead.get("suggested_modules", [])
        module_count = len(modules)

        if module_count <= 1:
            return "5-10 minutes"
        elif module_count <= 3:
            return "10-20 minutes"
        else:
            return "20-30 minutes"

    def _predict_potential_findings(self, lead: Dict[str, Any]) -> List[str]:
        """Predict what might be found"""
        target_type = lead.get("target_type", "unknown")

        predictions = {
            "email": [
                "Breach exposure",
                "Social media accounts",
                "Associated services",
            ],
            "domain": [
                "Subdomains",
                "DNS records",
                "SSL certificates",
                "Server information",
            ],
            "ip": [
                "Open ports",
                "Hosted services",
                "Geolocation",
                "Network information",
            ],
            "username": ["Social profiles", "Forum accounts", "Code repositories"],
        }

        return predictions.get(target_type, ["Additional intelligence"])

    def _identify_patterns(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Identify patterns in findings"""
        patterns = []

        # Domain patterns
        domains = [
            f.get("value", "") for f in findings if f.get("finding_type") == "domain"
        ]
        if len(domains) > 3:
            patterns.append(
                f"Multiple domains identified ({len(domains)}), suggesting complex infrastructure"
            )

        # Email patterns
        emails = [
            f.get("value", "") for f in findings if f.get("finding_type") == "email"
        ]
        if emails:
            email_domains = set(e.split("@")[1] for e in emails if "@" in e)
            if len(email_domains) == 1:
                patterns.append(
                    "All emails from same domain, indicating centralized organization"
                )

        return patterns if patterns else ["No clear patterns identified yet"]

    def _identify_connections(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Identify connections between findings"""
        connections = []

        # Check for findings with relationships
        related_findings = [f for f in findings if f.get("related_findings")]
        if related_findings:
            connections.append(
                f"{len(related_findings)} findings have identified relationships"
            )

        return connections if connections else ["No connections mapped yet"]

    def _identify_anomalies(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Identify unusual findings"""
        anomalies = []

        # Check for low confidence findings
        low_confidence = [f for f in findings if f.get("confidence", 1.0) < 0.5]
        if low_confidence:
            anomalies.append(
                f"{len(low_confidence)} findings have low confidence - require verification"
            )

        return anomalies if anomalies else ["No unusual patterns detected"]

    def _explain_overall_significance(
        self, investigation_data: Dict[str, Any], findings: List[Dict[str, Any]]
    ) -> str:
        """Explain overall significance of the investigation"""
        return f"""
This investigation provides insight into the digital footprint and security posture of the target(s).
The {len(findings)} findings collected represent potential security exposures, intelligence leads,
and areas requiring attention. This information can be used for security assessment, threat analysis,
and informed decision-making about protective measures.
        """.strip()

    def _calculate_progress(
        self, findings: List[Dict[str, Any]], leads: List[Dict[str, Any]]
    ) -> float:
        """Calculate investigation progress"""
        if not leads:
            return 100.0
        completed = len([lead for lead in leads if lead.get("status") == "completed"])
        return (completed / len(leads)) * 100

    def _rate_significance(self, finding: Dict[str, Any]) -> str:
        """Rate significance of a finding"""
        finding_type = finding.get("finding_type", "")
        confidence = finding.get("confidence", 0.5)

        if finding_type in ["breach", "vulnerability"] or confidence > 0.9:
            return "High"
        elif confidence > 0.7:
            return "Medium"
        else:
            return "Low"

    def _get_risk_recommendation(self, level: str) -> str:
        """Get recommendation based on risk level"""
        recommendations = {
            "High": "Immediate action required - review and remediate high-risk findings",
            "Medium": "Action recommended - address findings within 1-2 weeks",
            "Low": "Monitor situation - review findings periodically",
        }
        return recommendations.get(level, "Continue investigation")
