"""
Enhanced Reporting Engine
Generate comprehensive intelligence reports with PDF generation, executive summaries,
automated scheduling, and professional formatting.
"""

import json
import os
import smtplib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Image,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    # from reportlab.platypus.flowables import KeepTogether, PageBreak  # Unused

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import matplotlib
    import matplotlib.pyplot as plt

    matplotlib.use("Agg")  # Use non-interactive backend
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import plotly.io as pio

    try:
        pio.kaleido.scope.default_format = "png"
    except (AttributeError, TypeError):
        # kaleido not available or not properly configured
        pass
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    # import pandas as pd  # Unused

    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

from core.investigation_tracker import InvestigationTracker
from graph.adapter import GraphAdapter, get_default_graph


@dataclass
class ReportTemplate:
    """Report template configuration"""

    name: str
    title: str
    template_path: str
    styles: Dict[str, Any] = field(default_factory=dict)
    sections: List[str] = field(default_factory=list)


@dataclass
class ReportSchedule:
    """Scheduled report configuration"""

    report_id: str
    name: str
    template: str
    frequency: str  # daily, weekly, monthly
    recipients: List[str]
    filters: Dict[str, Any] = field(default_factory=dict)
    next_run: Optional[datetime] = None
    enabled: bool = True


class EnhancedReportingEngine:
    """Enhanced engine for generating professional intelligence reports"""

    def __init__(
        self,
        ai_engine=None,
        template_dir: str = "templates/reports",
        output_dir: str = "output/reports",
        tracker: Optional[InvestigationTracker] = None,
        graph: Optional[GraphAdapter] = None,
    ):
        self.ai_engine = ai_engine
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        self.templates: Dict[str, ReportTemplate] = {}
        self.schedules: Dict[str, ReportSchedule] = {}

        self.tracker = tracker or InvestigationTracker()
        self.graph = graph or get_default_graph()

        # Create directories
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize default templates
        self._load_default_templates()

        # Report generation statistics
        self.stats = {
            "reports_generated": 0,
            "pdf_reports": 0,
            "emails_sent": 0,
            "scheduled_reports": 0,
        }

    def _load_default_templates(self):
        """Load default report templates"""
        # Executive Summary Template
        exec_template = ReportTemplate(
            name="executive_summary",
            title="Executive Intelligence Summary",
            template_path="executive_summary.html",
            sections=[
                "header",
                "executive_summary",
                "key_findings",
                "risk_assessment",
                "recommendations",
                "appendices",
            ],
            styles={
                "header_color": "#1a365d",
                "risk_high": "#dc3545",
                "risk_medium": "#ffc107",
                "risk_low": "#28a745",
            },
        )

        # Comprehensive Investigation Report
        comp_template = ReportTemplate(
            name="comprehensive",
            title="Comprehensive Intelligence Report",
            template_path="comprehensive_report.html",
            sections=[
                "cover",
                "table_of_contents",
                "executive_summary",
                "methodology",
                "findings",
                "analysis",
                "recommendations",
                "appendices",
            ],
            styles={
                "primary_color": "#2b6cb0",
                "secondary_color": "#718096",
                "accent_color": "#e53e3e",
            },
        )

        # Threat Intelligence Report
        threat_template = ReportTemplate(
            name="threat_intelligence",
            title="Threat Intelligence Report",
            template_path="threat_report.html",
            sections=[
                "header",
                "threat_summary",
                "indicators",
                "tactics_techniques",
                "mitigation",
                "intelligence_gaps",
            ],
            styles={
                "threat_color": "#c53030",
                "warning_color": "#d69e2e",
                "info_color": "#3182ce",
            },
        )

        self.templates = {
            "executive_summary": exec_template,
            "comprehensive": comp_template,
            "threat_intelligence": threat_template,
        }

    def build_dataset(self, investigation_id: str) -> Dict[str, Any]:
        """Assemble a reporting dataset from tracker and graph state."""

        summary = self.tracker.get_investigation_summary(investigation_id)
        if not summary:
            return {}

        findings = [asdict(finding) for finding in self.tracker.get_all_findings(investigation_id)]
        leads = [asdict(lead) for lead in self.tracker.get_all_leads(investigation_id)]

        dataset = {
            "investigation_id": investigation_id,
            "name": summary.get("name", investigation_id),
            "summary": summary,
            "findings": findings,
            "leads": leads,
            "statistics": self._compute_statistics(findings, leads),
            "graph": self.graph.export_snapshot(),
        }

        return dataset

    def generate_executive_summary(
        self, investigation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate an executive summary report"""
        summary = {
            "investigation_id": investigation_data.get("investigation_id", "Unknown"),
            "generated_at": datetime.now().isoformat(),
            "title": "Executive Intelligence Summary",
            "key_findings": self._extract_key_findings(investigation_data),
            "risk_assessment": self._calculate_risk_score(investigation_data),
            "recommendations": self._generate_prioritized_recommendations(
                investigation_data
            ),
            "timeline": self._create_executive_timeline(investigation_data),
            "confidence_score": self._calculate_confidence_score(investigation_data),
        }

        return summary

    def _compute_statistics(
        self, findings: List[Dict[str, Any]], leads: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        findings_by_type: Dict[str, Dict[str, Any]] = {}
        module_usage: Dict[str, int] = {}
        latest_observation: Optional[datetime] = None

        for finding in findings:
            ftype = finding.get("finding_type", "unknown")
            entry = findings_by_type.setdefault(
                ftype,
                {
                    "count": 0,
                    "total_confidence": 0.0,
                    "sources": set(),
                    "latest": None,
                },
            )
            entry["count"] += 1
            entry["total_confidence"] += float(finding.get("confidence", 0.0))
            entry["sources"].add(finding.get("source_module", "unknown"))

            timestamp = finding.get("discovered_at")
            dt: Optional[datetime] = None
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    else:
                        dt = dt.astimezone(timezone.utc)
                except Exception:
                    dt = None

            if dt and (entry["latest"] is None or dt > entry["latest"]):
                entry["latest"] = dt
            if dt and (latest_observation is None or dt > latest_observation):
                latest_observation = dt

            module = finding.get("source_module", "unknown")
            module_usage[module] = module_usage.get(module, 0) + 1

        for entry in findings_by_type.values():
            count = max(entry["count"], 1)
            entry["avg_confidence"] = round(entry["total_confidence"] / count, 2)
            entry["sources"] = sorted(entry["sources"])
            entry["latest"] = (
                entry["latest"].isoformat() if isinstance(entry["latest"], datetime) else None
            )
            del entry["total_confidence"]

        prioritized_leads = sorted(
            leads,
            key=lambda l: ("critical", "high", "medium", "low").index(l.get("priority", "low"))
            if l.get("priority") in {"critical", "high", "medium", "low"}
            else 4,
        )

        return {
            "findings_by_type": findings_by_type,
            "modules": module_usage,
            "latest_observation": latest_observation.isoformat()
            if latest_observation
            else None,
            "lead_count": len(leads),
            "high_priority_leads": [lead.get("id") for lead in prioritized_leads[:5]],
        }

    def generate_technical_report(
        self, investigation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a technical report with detailed findings"""
        technical_report = {
            "investigation_id": investigation_data.get("investigation_id", "Unknown"),
            "generated_at": datetime.now().isoformat(),
            "title": "Technical Intelligence Report",
            "methodology": self._generate_methodology_section(investigation_data),
            "technical_findings": self._extract_technical_findings(investigation_data),
            "infrastructure_analysis": self._analyze_infrastructure(investigation_data),
            "vulnerability_assessment": self._assess_vulnerabilities(
                investigation_data
            ),
            "technical_recommendations": self._generate_technical_recommendations(
                investigation_data
            ),
            "confidence_score": self._calculate_confidence_score(investigation_data),
        }

        return technical_report

    def generate_threat_assessment(
        self, investigation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a threat assessment report"""
        threat_assessment = {
            "investigation_id": investigation_data.get("investigation_id", "Unknown"),
            "generated_at": datetime.now().isoformat(),
            "title": "Threat Intelligence Assessment",
            "threat_actors": self._identify_threat_actors(investigation_data),
            "attack_vectors": self._analyze_attack_vectors(investigation_data),
            "threat_indicators": self._extract_threat_indicators(investigation_data),
            "mitigation_strategies": self._generate_mitigation_strategies(
                investigation_data
            ),
            "risk_assessment": self._calculate_risk_score(investigation_data),
            "confidence_score": self._calculate_confidence_score(investigation_data),
        }

        return threat_assessment

    def generate_custom_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a custom report based on provided data"""
        custom_report = {
            "investigation_id": report_data.get("investigation_id", "Unknown"),
            "generated_at": datetime.now().isoformat(),
            "title": report_data.get("title", "Custom Intelligence Report"),
            "custom_sections": report_data.get("custom_sections", []),
            "intelligence_data": report_data.get("intelligence_data", {}),
            "style": report_data.get("style", "professional"),
            "length": report_data.get("length", "medium"),
            "include_charts": report_data.get("include_charts", True),
            "confidence_score": self._calculate_confidence_score(
                report_data.get("intelligence_data", {})
            ),
        }

        return custom_report

    def generate_pdf_report(
        self,
        report_data: Dict[str, Any],
        template_name: str = "executive_summary",
        filename: Optional[str] = None,
    ) -> str:
        """Generate a professional PDF report"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "reportlab is required for PDF generation. Install with: pip install reportlab"
            )

        if template_name not in self.templates:
            raise ValueError(f"Template '{template_name}' not found")

        template = self.templates[template_name]

        # Generate filename if not provided
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{template_name}_{timestamp}.pdf"

        filepath = self.output_dir / filename

        # Create PDF document
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )

        # Build the PDF content
        story = self._build_pdf_content(report_data, template)

        # Generate PDF
        doc.build(story)

        self.stats["pdf_reports"] += 1
        self.stats["reports_generated"] += 1

        return str(filepath)

    def _build_pdf_content(
        self, report_data: Dict[str, Any], template: ReportTemplate
    ) -> List:
        """Build PDF content elements"""
        story = []
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            spaceAfter=30,
            alignment=1,  # Center alignment
            textColor=colors.HexColor(template.styles.get("header_color", "#1a365d")),
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.HexColor(template.styles.get("primary_color", "#2b6cb0")),
        )

        # Title
        story.append(Paragraph(template.title, title_style))
        story.append(Spacer(1, 12))

        # Generation info
        gen_info = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        if "investigation_id" in report_data:
            gen_info += f" | Investigation ID: {report_data['investigation_id']}"

        story.append(Paragraph(gen_info, styles["Italic"]))
        story.append(Spacer(1, 20))

        # Executive Summary
        if "executive_summary" in report_data:
            story.append(Paragraph("Executive Summary", heading_style))
            summary_text = report_data["executive_summary"]
            story.append(Paragraph(summary_text, styles["Normal"]))
            story.append(Spacer(1, 20))

        # Key Findings
        if "key_findings" in report_data:
            story.append(Paragraph("Key Findings", heading_style))
            findings = report_data["key_findings"]
            if isinstance(findings, list):
                for i, finding in enumerate(findings, 1):
                    story.append(Paragraph(f"{i}. {finding}", styles["Normal"]))
                    story.append(Spacer(1, 6))
            story.append(Spacer(1, 20))

        # Risk Assessment
        if "risk_assessment" in report_data:
            story.append(Paragraph("Risk Assessment", heading_style))
            risk_data = report_data["risk_assessment"]

            # Create risk table
            risk_table_data = [
                ["Risk Level", "Score", "Description"],
                [
                    risk_data.get("level", "Unknown"),
                    str(risk_data.get("score", "N/A")),
                    risk_data.get("description", "N/A"),
                ],
            ]

            risk_table = Table(risk_table_data)
            risk_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 14),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ]
                )
            )

            story.append(risk_table)
            story.append(Spacer(1, 20))

        # Recommendations
        if "recommendations" in report_data:
            story.append(Paragraph("Recommendations", heading_style))
            recommendations = report_data["recommendations"]
            if isinstance(recommendations, list):
                for i, rec in enumerate(recommendations, 1):
                    story.append(Paragraph(f"{i}. {rec}", styles["Normal"]))
                    story.append(Spacer(1, 6))
            story.append(Spacer(1, 20))

        # Add charts if matplotlib is available
        if MATPLOTLIB_AVAILABLE and "charts" in report_data:
            story.append(Paragraph("Visual Analysis", heading_style))
            for chart_data in report_data["charts"]:
                chart_img = self._generate_chart_image(chart_data)
                if chart_img:
                    story.append(chart_img)
                    story.append(Spacer(1, 12))

        return story

    def _generate_chart_image(self, chart_data: Dict[str, Any]) -> Optional[Any]:
        """Generate chart image for PDF inclusion"""
        try:
            fig, ax = plt.subplots(figsize=(8, 6))

            chart_type = chart_data.get("type", "bar")
            if chart_type == "bar":
                ax.bar(chart_data.get("labels", []), chart_data.get("values", []))
            elif chart_type == "pie":
                ax.pie(
                    chart_data.get("values", []),
                    labels=chart_data.get("labels", []),
                    autopct="%1.1f%%",
                )
            elif chart_type == "line":
                ax.plot(chart_data.get("labels", []), chart_data.get("values", []))

            ax.set_title(chart_data.get("title", "Chart"))
            plt.tight_layout()

            # Save to BytesIO
            img_buffer = BytesIO()
            plt.savefig(img_buffer, format="png", dpi=150, bbox_inches="tight")
            plt.close(fig)
            img_buffer.seek(0)

            # Create ReportLab Image
            img = Image(img_buffer)
            img.drawHeight = 3 * inch
            img.drawWidth = 6 * inch

            return img
        except Exception as e:
            print(f"Error generating chart: {e}")
            return None

    def _extract_key_findings(self, data: Dict[str, Any]) -> List[str]:
        """Extract key findings from investigation data"""

        stats = data.get("statistics", {}).get("findings_by_type", {})
        if not stats:
            return ["No findings have been recorded for this investigation yet."]

        sorted_types = sorted(
            stats.items(), key=lambda item: item[1]["count"], reverse=True
        )

        findings: List[str] = []
        for ftype, meta in sorted_types[:5]:
            message = (
                f"{meta['count']} {ftype} finding(s) with average confidence "
                f"{meta['avg_confidence']:.2f}."
            )
            if meta.get("latest"):
                message += f" Most recent observation on {meta['latest']}."
            if meta.get("sources"):
                message += f" Sources: {', '.join(meta['sources'])}."
            findings.append(message)

        leads = data.get("leads", [])
        high_priority = [
            lead for lead in leads if lead.get("priority") in {"critical", "high"}
        ]
        if high_priority:
            lead_targets = ", ".join(lead["target"] for lead in high_priority[:3])
            findings.append(
                f"{len(high_priority)} high-priority lead(s) awaiting action: {lead_targets}."
            )

        return findings

    def _calculate_risk_score(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score"""

        leads = data.get("leads", [])
        findings = data.get("findings", [])

        priority_weight = {"critical": 25, "high": 20, "medium": 10, "low": 5}
        score = 0
        drivers: List[str] = []

        for lead in leads:
            priority = lead.get("priority", "low")
            score += priority_weight.get(priority, 5)
            drivers.append(f"Lead {lead.get('target')} ({priority})")

        exposure_findings = [
            f
            for f in findings
            if f.get("finding_type") in {"breach", "vulnerability", "threat_indicator"}
        ]
        if exposure_findings:
            score += len(exposure_findings) * 5
            drivers.append(
                f"{len(exposure_findings)} exposure indicator(s) detected"
            )

        score = min(score, 100)

        if score >= 70:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 30:
            level = "medium"
        else:
            level = "low"

        return {"score": score, "level": level, "drivers": drivers[:6]}

    def _generate_prioritized_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Generate prioritized recommendations"""

        recommendations: List[str] = []
        risk = self._calculate_risk_score(data)

        if risk["level"] in {"critical", "high"}:
            recommendations.append("Escalate investigation to incident response immediately.")
            recommendations.append("Task dedicated owners for each high-priority lead.")
        elif risk["level"] == "medium":
            recommendations.append("Schedule targeted follow-up collection on active leads.")
        else:
            recommendations.append("Maintain routine monitoring cadence.")

        leads = data.get("leads", [])
        sorted_leads = sorted(
            leads,
            key=lambda l: ("critical", "high", "medium", "low").index(l.get("priority", "low"))
            if l.get("priority") in {"critical", "high", "medium", "low"}
            else 4,
        )

        for lead in sorted_leads[:5]:
            modules = ", ".join(lead.get("suggested_modules", [])) or "core modules"
            recommendations.append(
                f"Investigate {lead['target']} ({lead['priority']}) using {modules}."
            )

        coverage = data.get("statistics", {}).get("findings_by_type", {})
        if "domain" not in coverage and "subdomain" not in coverage:
            recommendations.append("Collect domain intelligence to map external surface.")
        if "breach" not in coverage:
            recommendations.append("Query breach repositories for credential exposure.")

        return recommendations

    def _create_executive_timeline(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create executive timeline of key events"""
        timeline: List[Dict[str, Any]] = []

        summary = data.get("summary", {})
        stored_timeline = summary.get("timeline")
        if stored_timeline:
            try:
                parsed = json.loads(stored_timeline)
                if isinstance(parsed, list):
                    for entry in parsed:
                        timeline.append(
                            {
                                "timestamp": entry.get("timestamp"),
                                "event": entry.get("event") or entry.get("description"),
                                "impact": entry.get("impact", "medium"),
                            }
                        )
            except Exception:
                pass

        if not timeline:
            sorted_findings = sorted(
                data.get("findings", []),
                key=lambda f: f.get("discovered_at", ""),
                reverse=True,
            )
            for finding in sorted_findings[:10]:
                timeline.append(
                    {
                        "timestamp": finding.get("discovered_at"),
                        "event": f"Finding recorded: {finding.get('finding_type')} {finding.get('value')}",
                        "impact": "high" if finding.get("confidence", 0) >= 0.8 else "medium",
                    }
                )

        if not timeline:
            timeline.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "event": "Investigation initiated",
                    "impact": "low",
                }
            )

        return timeline[:10]

    def _calculate_confidence_score(self, data: Dict[str, Any]) -> float:
        """Calculate confidence score for the investigation"""

        confidences = [
            float(f.get("confidence", 0.0))
            for f in data.get("findings", [])
            if f.get("confidence") is not None
        ]

        if not confidences:
            return 0.3

        avg = sum(confidences) / len(confidences)
        return round(min(max(avg, 0.1), 1.0), 2)

    def _generate_methodology_section(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate methodology section for technical reports"""
        modules = data.get("statistics", {}).get("modules", {})
        return {
            "data_sources": sorted(modules.keys()),
            "collection_count": sum(modules.values()),
            "collection_methods": ["passive_intelligence", "open_source"],
            "analysis_framework": "intelligence_cycle",
            "tools_used": sorted(modules.keys()) or ["osint_suite"],
        }

    def _extract_technical_findings(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract technical findings from investigation data"""
        findings: List[Dict[str, Any]] = []
        stats = data.get("statistics", {}).get("findings_by_type", {})

        for category in ["domain", "subdomain", "ip", "email", "profile", "company"]:
            if category in stats:
                meta = stats[category]
                findings.append(
                    {
                        "category": category,
                        "findings": [
                            f"{meta['count']} artifacts with average confidence {meta['avg_confidence']:.2f}"
                        ],
                        "severity": "high"
                        if category in {"domain", "ip"}
                        else "medium",
                    }
                )

        return findings

    def _analyze_infrastructure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze infrastructure from investigation data"""
        stats = data.get("statistics", {}).get("findings_by_type", {})
        providers = {
            finding.get("metadata", {}).get("org")
            for finding in data.get("findings", [])
            if finding.get("finding_type") == "service_provider"
            and finding.get("metadata", {}).get("org")
        }

        return {
            "domain_count": stats.get("domain", {}).get("count", 0)
            + stats.get("subdomain", {}).get("count", 0),
            "ip_count": stats.get("ip", {}).get("count", 0),
            "service_providers": sorted(providers),
            "latest_observation": data.get("statistics", {}).get("latest_observation"),
        }

    def _assess_vulnerabilities(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Assess vulnerabilities from investigation data"""
        vulnerabilities: List[Dict[str, Any]] = []
        for finding in data.get("findings", []):
            ftype = finding.get("finding_type")
            if ftype in {"breach", "vulnerability"}:
                vulnerabilities.append(
                    {
                        "type": ftype,
                        "severity": "high" if finding.get("confidence", 0) >= 0.7 else "medium",
                        "description": finding.get("value"),
                    }
                )
        return vulnerabilities

    def _generate_technical_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Generate technical recommendations"""
        recommendations: List[str] = []
        coverage = data.get("statistics", {}).get("findings_by_type", {})

        if coverage.get("subdomain", {}).get("count", 0) > 0:
            recommendations.append("Deploy continuous subdomain discovery to track infrastructure growth.")
        if coverage.get("ip", {}).get("count", 0) > 0:
            recommendations.append("Baseline discovered IP assets and monitor for reputation changes.")

        if "breach" not in coverage:
            recommendations.append("Integrate credential breach monitoring to detect exposure early.")

        return recommendations

    def _identify_threat_actors(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify potential threat actors"""
        actors: List[Dict[str, Any]] = []
        for lead in data.get("leads", []):
            if lead.get("target_type") in {"profile", "company"}:
                actors.append(
                    {
                        "type": lead.get("target_type"),
                        "name": lead.get("target"),
                        "confidence": 0.6 if lead.get("priority") == "medium" else 0.8,
                        "indicators": lead.get("suggested_modules", []),
                    }
                )
        return actors

    def _analyze_attack_vectors(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze potential attack vectors"""
        vectors: List[Dict[str, Any]] = []
        findings = data.get("findings", [])
        if any(f.get("finding_type") == "email" for f in findings):
            vectors.append(
                {
                    "type": "phishing",
                    "likelihood": "high",
                    "description": "Discovered email addresses enable phishing attempts.",
                }
            )
        if any(f.get("finding_type") == "profile" for f in findings):
            vectors.append(
                {
                    "type": "social_engineering",
                    "likelihood": "medium",
                    "description": "Public profiles support impersonation and trust scams.",
                }
            )
        if any(f.get("finding_type") == "ip" for f in findings):
            vectors.append(
                {
                    "type": "network_intrusion",
                    "likelihood": "medium",
                    "description": "Observed infrastructure may be targeted for direct intrusion.",
                }
            )
        return vectors

    def _extract_threat_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract threat indicators"""
        indicators: List[Dict[str, Any]] = []
        for finding in data.get("findings", []):
            if finding.get("confidence", 0) >= 0.6:
                indicators.append(
                    {
                        "type": finding.get("finding_type"),
                        "value": finding.get("value"),
                        "confidence": round(float(finding.get("confidence", 0)), 2),
                        "source": finding.get("source_module"),
                    }
                )
        return indicators

    def _generate_mitigation_strategies(self, data: Dict[str, Any]) -> List[str]:
        """Generate mitigation strategies"""
        strategies: List[str] = []
        risk = self._calculate_risk_score(data)

        if risk["level"] in {"critical", "high"}:
            strategies.extend(
                [
                    "Deploy enhanced monitoring and alerting on flagged assets.",
                    "Harden exposed infrastructure and rotate credentials immediately.",
                ]
            )
        elif risk["level"] == "medium":
            strategies.extend(
                [
                    "Increase log review frequency for identified assets.",
                    "Validate third-party exposure remediation steps.",
                ]
            )
        else:
            strategies.append("Maintain baseline monitoring and revisit after new findings.")

        return strategies

    def schedule_report(self, schedule: ReportSchedule) -> str:
        """Schedule a recurring report"""
        schedule_id = schedule.report_id
        self.schedules[schedule_id] = schedule

        # Calculate next run time
        now = datetime.now()
        if schedule.frequency == "daily":
            schedule.next_run = now.replace(
                hour=9, minute=0, second=0, microsecond=0
            ) + timedelta(days=1)
        elif schedule.frequency == "weekly":
            days_ahead = (7 - now.weekday()) % 7
            if days_ahead == 0:
                days_ahead = 7
            schedule.next_run = (now + timedelta(days=days_ahead)).replace(
                hour=9, minute=0, second=0, microsecond=0
            )
        elif schedule.frequency == "monthly":
            next_month = now.replace(day=1) + timedelta(days=32)
            schedule.next_run = next_month.replace(
                day=1, hour=9, minute=0, second=0, microsecond=0
            )

        self.stats["scheduled_reports"] += 1
        return schedule_id

    def send_report_email(
        self, report_path: str, recipients: List[str], subject: str, body: str
    ) -> bool:
        """Send report via email"""
        try:
            # Email configuration from environment variables
            smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
            smtp_port = int(os.getenv("SMTP_PORT", "587"))
            sender_email = os.getenv("SMTP_SENDER_EMAIL", "reports@osint-suite.local")
            sender_password = os.getenv("SMTP_SENDER_PASSWORD")

            if not sender_password:
                raise ValueError(
                    "SMTP_SENDER_PASSWORD environment variable must be set"
                )

            # Create message
            msg = MIMEMultipart()
            msg["From"] = sender_email
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject

            msg.attach(MIMEText(body, "html"))

            # Attach PDF
            with open(report_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename={os.path.basename(report_path)}",
                )
                msg.attach(part)

            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            text = msg.as_string()
            server.sendmail(sender_email, recipients, text)
            server.quit()

            self.stats["emails_sent"] += 1
            return True

        except Exception as e:
            print(f"Error sending email: {e}")
            return False

    def process_scheduled_reports(self) -> List[str]:
        """Process all due scheduled reports"""
        processed = []
        now = datetime.now()

        for schedule_id, schedule in self.schedules.items():
            if not schedule.enabled or schedule.next_run is None:
                continue

            if now >= schedule.next_run:
                try:
                    # Generate report data (would be fetched from investigation store)
                    report_data = {
                        "investigation_id": f"scheduled_{schedule_id}",
                        "generated_at": now.isoformat(),
                        "title": schedule.name,
                        "executive_summary": f"Scheduled {schedule.frequency} report for {schedule.name}",
                        "key_findings": [
                            "Scheduled report generation",
                            "Automated intelligence delivery",
                        ],
                        "recommendations": [
                            "Review report contents",
                            "Take appropriate actions",
                        ],
                    }

                    # Generate PDF
                    pdf_path = self.generate_pdf_report(report_data, schedule.template)

                    # Send email
                    if schedule.recipients:
                        subject = f"OSINT Report: {schedule.name}"
                        body = f"""
                        <h2>Scheduled OSINT Report</h2>
                        <p>A new {schedule.frequency} intelligence report has been generated.</p>
                        <p>Report: {schedule.name}</p>
                        <p>Generated: {now.strftime("%Y-%m-%d %H:%M:%S")}</p>
                        <p>Please find the detailed report attached.</p>
                        """

                        self.send_report_email(
                            pdf_path, schedule.recipients, subject, body
                        )

                    # Update next run time
                    if schedule.frequency == "daily":
                        schedule.next_run = schedule.next_run + timedelta(days=1)
                    elif schedule.frequency == "weekly":
                        schedule.next_run = schedule.next_run + timedelta(weeks=1)
                    elif schedule.frequency == "monthly":
                        next_month = schedule.next_run.replace(day=1) + timedelta(
                            days=32
                        )
                        schedule.next_run = next_month.replace(day=1)

                    processed.append(schedule_id)

                except Exception as e:
                    print(f"Error processing scheduled report {schedule_id}: {e}")

        return processed

    def get_stats(self) -> Dict[str, int]:
        """Get reporting engine statistics"""
        return self.stats.copy()
