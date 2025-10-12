"""
Enhanced Reporting Engine
Generate comprehensive intelligence reports with PDF generation, executive summaries,
automated scheduling, and professional formatting.
"""

import os
import smtplib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO
from pathlib import Path
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
    ):
        self.ai_engine = ai_engine
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        self.templates: Dict[str, ReportTemplate] = {}
        self.schedules: Dict[str, ReportSchedule] = {}

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
        findings = []

        # Analyze different data sources
        if "domain_data" in data:
            domain_findings = self._analyze_domain_findings(data["domain_data"])
            findings.extend(domain_findings)

        if "ip_data" in data:
            ip_findings = self._analyze_ip_findings(data["ip_data"])
            findings.extend(ip_findings)

        if "social_data" in data:
            social_findings = self._analyze_social_findings(data["social_data"])
            findings.extend(social_findings)

        if "breach_data" in data:
            breach_findings = self._analyze_breach_findings(data["breach_data"])
            findings.extend(breach_findings)

        return findings[:10]  # Limit to top 10 findings

    def _analyze_domain_findings(self, domain_data: Dict[str, Any]) -> List[str]:
        """Analyze domain-related findings"""
        findings = []

        if domain_data.get("subdomains_found", 0) > 10:
            findings.append(
                f"Discovered {domain_data['subdomains_found']} subdomains, indicating extensive infrastructure"
            )

        if domain_data.get("recent_registrations", False):
            findings.append(
                "Recent domain registrations detected, possible new campaign infrastructure"
            )

        if domain_data.get("suspicious_patterns", []):
            findings.append(
                f"Identified {len(domain_data['suspicious_patterns'])} suspicious domain patterns"
            )

        return findings

    def _analyze_ip_findings(self, ip_data: Dict[str, Any]) -> List[str]:
        """Analyze IP-related findings"""
        findings = []

        if ip_data.get("blacklisted_ips", 0) > 0:
            findings.append(
                f"{ip_data['blacklisted_ips']} IP addresses found on security blacklists"
            )

        if ip_data.get("cloud_providers", []):
            findings.append(
                f"Infrastructure hosted on {', '.join(ip_data['cloud_providers'])}"
            )

        if ip_data.get("geographic_distribution", {}):
            countries = list(ip_data["geographic_distribution"].keys())
            if len(countries) > 3:
                findings.append(
                    f"Global infrastructure spanning {len(countries)} countries"
                )

        return findings

    def _analyze_social_findings(self, social_data: Dict[str, Any]) -> List[str]:
        """Analyze social media findings"""
        findings = []

        if social_data.get("total_profiles", 0) > 5:
            findings.append(
                f"Found {social_data['total_profiles']} social media profiles across platforms"
            )

        if social_data.get("recent_activity", []):
            findings.append(
                "Recent social media activity detected, indicating active operations"
            )

        if social_data.get("connections_found", 0) > 10:
            findings.append(
                f"Identified {social_data['connections_found']} social connections and relationships"
            )

        return findings

    def _analyze_breach_findings(self, breach_data: Dict[str, Any]) -> List[str]:
        """Analyze breach-related findings"""
        findings = []

        if breach_data.get("total_breaches", 0) > 0:
            findings.append(
                f"Target appears in {breach_data['total_breaches']} data breaches"
            )

        if breach_data.get("sensitive_data_exposed", False):
            findings.append(
                "Sensitive personal or financial data found in breach databases"
            )

        if breach_data.get("recent_breaches", []):
            findings.append(
                "Recent breach activity detected, indicating ongoing exposure risk"
            )

        return findings

    def _calculate_risk_score(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score"""
        risk_score = 0
        risk_factors = []

        # Domain risk factors
        if data.get("domain_data", {}).get("suspicious_patterns", []):
            risk_score += 20
            risk_factors.append("Suspicious domain patterns detected")

        # IP risk factors
        if data.get("ip_data", {}).get("blacklisted_ips", 0) > 0:
            risk_score += 25
            risk_factors.append("IP addresses on security blacklists")

        # Breach risk factors
        if data.get("breach_data", {}).get("total_breaches", 0) > 0:
            risk_score += 15
            risk_factors.append("Data found in breach databases")

        # Social risk factors
        social_count = data.get("social_data", {}).get("total_profiles", 0)
        if social_count > 10:
            risk_score += 10
            risk_factors.append("Extensive social media presence")

        # Determine risk level
        if risk_score >= 50:
            level = "Critical"
            color = "red"
        elif risk_score >= 30:
            level = "High"
            color = "orange"
        elif risk_score >= 15:
            level = "Medium"
            color = "yellow"
        else:
            level = "Low"
            color = "green"

        return {
            "score": risk_score,
            "level": level,
            "color": color,
            "description": f"Overall risk assessment: {level.lower()}",
            "factors": risk_factors,
        }

    def _generate_prioritized_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []

        risk_score = self._calculate_risk_score(data)["score"]

        if risk_score >= 50:
            recommendations.extend(
                [
                    "URGENT: Implement immediate containment measures",
                    "Conduct comprehensive security audit",
                    "Notify relevant authorities if criminal activity suspected",
                    "Isolate affected systems and accounts",
                ]
            )
        elif risk_score >= 30:
            recommendations.extend(
                [
                    "Increase monitoring of identified assets",
                    "Implement additional security controls",
                    "Conduct targeted security assessment",
                    "Review and update access controls",
                ]
            )
        elif risk_score >= 15:
            recommendations.extend(
                [
                    "Monitor identified assets regularly",
                    "Implement basic security hygiene",
                    "Conduct periodic security reviews",
                    "Maintain situational awareness",
                ]
            )
        else:
            recommendations.extend(
                [
                    "Continue standard security practices",
                    "Maintain regular monitoring",
                    "Stay informed about emerging threats",
                ]
            )

        # Add specific recommendations based on findings
        if data.get("breach_data", {}).get("total_breaches", 0) > 0:
            recommendations.append(
                "Change passwords for all affected accounts immediately"
            )

        if data.get("domain_data", {}).get("subdomains_found", 0) > 20:
            recommendations.append("Conduct comprehensive infrastructure mapping")

        return recommendations

    def _create_executive_timeline(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create executive timeline of key events"""
        timeline = []

        # Extract timeline events from various data sources
        if "domain_data" in data and "registration_date" in data["domain_data"]:
            timeline.append(
                {
                    "date": data["domain_data"]["registration_date"],
                    "event": "Domain registration",
                    "type": "domain",
                }
            )

        if "breach_data" in data and "breaches" in data["breach_data"]:
            for breach in data["breach_data"]["breaches"]:
                timeline.append(
                    {
                        "date": breach.get("date", "Unknown"),
                        "event": f"Data breach: {breach.get('source', 'Unknown')}",
                        "type": "breach",
                    }
                )

        # Sort by date
        timeline.sort(
            key=lambda x: x["date"] if x["date"] != "Unknown" else "1900-01-01",
            reverse=True,
        )

        return timeline[:10]  # Return most recent 10 events

    def _calculate_confidence_score(self, data: Dict[str, Any]) -> float:
        """Calculate confidence score for the investigation"""
        confidence = 0.5  # Base confidence

        # Increase confidence based on data sources
        data_sources = [
            "domain_data",
            "ip_data",
            "social_data",
            "breach_data",
            "email_data",
        ]
        sources_found = sum(
            1 for source in data_sources if source in data and data[source]
        )

        confidence += (sources_found / len(data_sources)) * 0.3

        # Increase confidence based on data quality
        if data.get("domain_data", {}).get("whois_complete", False):
            confidence += 0.1

        if data.get("ip_data", {}).get("geolocation_complete", False):
            confidence += 0.1

        return min(confidence, 1.0)

    def _generate_methodology_section(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate methodology section for technical reports"""
        return {
            "data_sources": list(data.keys()),
            "collection_methods": ["passive_intelligence", "osint_techniques"],
            "analysis_framework": "intelligence_cycle",
            "tools_used": ["osint_suite", "custom_modules"],
        }

    def _extract_technical_findings(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract technical findings from investigation data"""
        findings = []

        # Add technical details from various sources
        if "domain_data" in data:
            findings.append(
                {
                    "category": "domain",
                    "findings": self._analyze_domain_findings(data["domain_data"]),
                    "severity": "medium",
                }
            )

        if "ip_data" in data:
            findings.append(
                {
                    "category": "network",
                    "findings": self._analyze_ip_findings(data["ip_data"]),
                    "severity": "high",
                }
            )

        return findings

    def _analyze_infrastructure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze infrastructure from investigation data"""
        return {
            "domains": data.get("domain_data", {}),
            "ip_addresses": data.get("ip_data", {}),
            "services": data.get("service_data", {}),
            "geographic_distribution": data.get("geo_data", {}),
        }

    def _assess_vulnerabilities(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Assess vulnerabilities from investigation data"""
        vulnerabilities = []

        # Check for common vulnerabilities
        if data.get("breach_data", {}).get("total_breaches", 0) > 0:
            vulnerabilities.append(
                {
                    "type": "data_breach",
                    "severity": "high",
                    "description": "Data found in breach databases",
                }
            )

        return vulnerabilities

    def _generate_technical_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Generate technical recommendations"""
        recommendations = []

        if data.get("domain_data", {}).get("subdomains_found", 0) > 10:
            recommendations.append("Implement comprehensive subdomain monitoring")

        if data.get("ip_data", {}).get("blacklisted_ips", 0) > 0:
            recommendations.append("Review and remediate blacklisted IP addresses")

        return recommendations

    def _identify_threat_actors(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify potential threat actors"""
        actors = []

        # Basic threat actor identification logic
        if data.get("breach_data", {}).get("total_breaches", 0) > 0:
            actors.append(
                {
                    "type": "cyber_criminal",
                    "confidence": 0.7,
                    "indicators": ["data_breach_activity"],
                }
            )

        return actors

    def _analyze_attack_vectors(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze potential attack vectors"""
        vectors = []

        if data.get("social_data", {}).get("total_profiles", 0) > 0:
            vectors.append(
                {
                    "type": "social_engineering",
                    "likelihood": "medium",
                    "description": "Social media presence enables targeted attacks",
                }
            )

        return vectors

    def _extract_threat_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract threat indicators"""
        indicators = []

        if data.get("domain_data", {}).get("suspicious_patterns"):
            indicators.append(
                {
                    "type": "domain",
                    "value": "suspicious_domain_patterns",
                    "confidence": 0.8,
                }
            )

        return indicators

    def _generate_mitigation_strategies(self, data: Dict[str, Any]) -> List[str]:
        """Generate mitigation strategies"""
        strategies = []

        risk_score = self._calculate_risk_score(data)["score"]

        if risk_score > 30:
            strategies.append("Implement enhanced monitoring and alerting")
            strategies.append("Conduct regular security assessments")

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
                        <p>Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}</p>
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
