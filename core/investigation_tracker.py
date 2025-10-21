#!/usr/bin/env python3
"""
Investigation Tracker
Persistent tracking of investigation findings with progressive building
Ensures no data loss and maintains complete investigation history
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.storage_config import resolve_path

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Individual investigation finding"""

    id: str
    investigation_id: str
    finding_type: str  # email, domain, ip, subdomain, breach, etc.
    value: str
    source_module: str
    discovered_at: str
    confidence: float
    metadata: Dict[str, Any]
    related_findings: List[str]  # IDs of related findings
    follow_up_status: str  # pending, in_progress, completed, skipped
    notes: str


@dataclass
class InvestigationLead:
    """Potential investigation lead"""

    id: str
    investigation_id: str
    target: str
    target_type: str
    reason: str
    priority: str  # critical, high, medium, low
    suggested_modules: List[str]
    created_at: str
    status: str  # pending, investigating, completed, dismissed
    findings_count: int
    estimated_value: str  # high, medium, low


class InvestigationTracker:
    """
    Track and catalog all investigation findings with persistent storage.
    Builds progressively without losing data.
    """

    def __init__(self, storage_path: Optional[str] = None):
        base_path = Path(storage_path) if storage_path else resolve_path("investigation")
        base_path.mkdir(exist_ok=True, parents=True)

        self.storage_path = base_path
        self.db_path = self.storage_path / "investigation_tracker.db"
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database with tables for findings and leads"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source_module TEXT NOT NULL,
                discovered_at TEXT NOT NULL,
                confidence REAL NOT NULL,
                metadata TEXT NOT NULL,
                related_findings TEXT,
                follow_up_status TEXT DEFAULT 'pending',
                notes TEXT DEFAULT '',
                UNIQUE(investigation_id, finding_type, value, source_module)
            )
        """)

        # Investigation leads table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS leads (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                priority TEXT NOT NULL,
                suggested_modules TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                findings_count INTEGER DEFAULT 0,
                estimated_value TEXT NOT NULL,
                updated_at TEXT,
                score REAL
            )
            """
        )

        # Backfill columns for installations created before score/updated_at existed
        cursor.execute("PRAGMA table_info(leads)")
        lead_columns = {row[1] for row in cursor.fetchall()}
        if "updated_at" not in lead_columns:
            cursor.execute("ALTER TABLE leads ADD COLUMN updated_at TEXT")
        if "score" not in lead_columns:
            cursor.execute("ALTER TABLE leads ADD COLUMN score REAL")

        # Investigation summary table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigation_summary (
                investigation_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0,
                total_leads INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                key_discoveries TEXT DEFAULT '[]',
                timeline TEXT DEFAULT '[]'
            )
        """)

        # Create indexes for faster queries
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_investigation ON findings(investigation_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_value ON findings(value)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_leads_investigation ON leads(investigation_id)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status)")

        conn.commit()
        conn.close()

        logger.info(f"Investigation tracker database initialized at {self.db_path}")

    def create_investigation(self, investigation_id: str, name: str) -> bool:
        """Create a new investigation tracking entry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            now = datetime.now().isoformat()
            cursor.execute(
                """
                INSERT INTO investigation_summary (investigation_id, name, created_at, updated_at)
                VALUES (?, ?, ?, ?)
            """,
                (investigation_id, name, now, now),
            )

            conn.commit()
            logger.info(f"Created investigation tracker for: {investigation_id}")
            return True
        except sqlite3.IntegrityError:
            logger.warning(f"Investigation {investigation_id} already exists")
            return False
        finally:
            conn.close()

    def add_finding(
        self,
        investigation_id: str,
        finding_type: str,
        value: str,
        source_module: str,
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Add a new finding to the investigation.
        Returns finding ID if added, None if duplicate.
        """
        finding_id = f"finding_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        now = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO findings (
                    id, investigation_id, finding_type, value, source_module,
                    discovered_at, confidence, metadata, related_findings
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    finding_id,
                    investigation_id,
                    finding_type,
                    value,
                    source_module,
                    now,
                    confidence,
                    json.dumps(metadata or {}),
                    json.dumps([]),
                ),
            )

            # Update investigation summary
            cursor.execute(
                """
                UPDATE investigation_summary
                SET total_findings = total_findings + 1,
                    updated_at = ?
                WHERE investigation_id = ?
            """,
                (now, investigation_id),
            )

            conn.commit()
            logger.info(f"Added finding: {finding_type} - {value}")
            return finding_id

        except sqlite3.IntegrityError:
            logger.debug(f"Duplicate finding ignored: {finding_type} - {value}")
            return None
        finally:
            conn.close()

    def upsert_lead(
        self,
        investigation_id: str,
        target: str,
        target_type: str,
        reason: str,
        *,
        priority: str = "medium",
        suggested_modules: Optional[List[str]] = None,
        estimated_value: str = "medium",
        score: Optional[float] = None,
        findings_count: int = 0,
    ) -> str:
        """Insert a new lead or update the existing record if the target already exists."""

        now = datetime.now().isoformat()
        suggested_modules_json = json.dumps(suggested_modules or [])

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, priority, findings_count FROM leads WHERE investigation_id = ? AND target = ? AND target_type = ?",
            (investigation_id, target, target_type),
        )
        existing = cursor.fetchone()

        if existing:
            lead_id = existing[0]
            new_priority = priority
            if existing[1] == "critical" or priority == "critical":
                new_priority = "critical"
            elif existing[1] == "high" or priority == "high":
                new_priority = "high"

            current_count = existing[2] if isinstance(existing[2], (int, float)) else 0
            cursor.execute(
                """
                UPDATE leads
                SET reason = ?, priority = ?, suggested_modules = ?,
                    findings_count = ?, estimated_value = ?, updated_at = ?,
                    score = COALESCE(?, score)
                WHERE id = ?
                """,
                (
                    reason,
                    new_priority,
                    suggested_modules_json,
                    max(findings_count, current_count),
                    estimated_value,
                    now,
                    score,
                    lead_id,
                ),
            )
        else:
            lead_id = f"lead_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
            cursor.execute(
                """
                INSERT INTO leads (
                    id, investigation_id, target, target_type, reason,
                    priority, suggested_modules, created_at, estimated_value,
                    findings_count, score, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lead_id,
                    investigation_id,
                    target,
                    target_type,
                    reason,
                    priority,
                    suggested_modules_json,
                    now,
                    estimated_value,
                    findings_count,
                    score,
                    now,
                ),
            )

            cursor.execute(
                """
                UPDATE investigation_summary
                SET total_leads = total_leads + 1,
                    updated_at = ?
                WHERE investigation_id = ?
                """,
                (now, investigation_id),
            )

        conn.commit()
        conn.close()

        logger.info(f"Registered lead {target_type}:{target} for {investigation_id}")
        return lead_id

    def get_all_findings(
        self,
        investigation_id: str,
        finding_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Finding]:
        """Get all findings for an investigation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM findings WHERE investigation_id = ?"
        params = [investigation_id]

        if finding_type:
            query += " AND finding_type = ?"
            params.append(finding_type)

        if status:
            query += " AND follow_up_status = ?"
            params.append(status)

        query += " ORDER BY discovered_at DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        findings = []
        for row in rows:
            finding = Finding(
                id=row[0],
                investigation_id=row[1],
                finding_type=row[2],
                value=row[3],
                source_module=row[4],
                discovered_at=row[5],
                confidence=row[6],
                metadata=json.loads(row[7]),
                related_findings=json.loads(row[8] or "[]"),
                follow_up_status=row[9] or "pending",
                notes=row[10] or "",
            )
            findings.append(finding)

        return findings

    def get_all_leads(
        self,
        investigation_id: str,
        status: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[InvestigationLead]:
        """Get all investigation leads"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM leads WHERE investigation_id = ?"
        params = [investigation_id]

        if status:
            query += " AND status = ?"
            params.append(status)

        if priority:
            query += " AND priority = ?"
            params.append(priority)

        # Order by priority (critical > high > medium > low) and creation date
        query += ' ORDER BY CASE priority WHEN "critical" THEN 1 WHEN "high" THEN 2 WHEN "medium" THEN 3 ELSE 4 END, created_at DESC'

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        leads = []
        for row in rows:
            lead = InvestigationLead(
                id=row[0],
                investigation_id=row[1],
                target=row[2],
                target_type=row[3],
                reason=row[4],
                priority=row[5],
                suggested_modules=json.loads(row[6]),
                created_at=row[7],
                status=row[8],
                findings_count=row[9],
                estimated_value=row[10],
            )
            leads.append(lead)

        return leads

    def update_lead_status(
        self, lead_id: str, status: str, findings_count: Optional[int] = None
    ):
        """Update lead status and findings count"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if findings_count is not None:
            cursor.execute(
                """
                UPDATE leads
                SET status = ?, findings_count = ?
                WHERE id = ?
            """,
                (status, findings_count, lead_id),
            )
        else:
            cursor.execute(
                """
                UPDATE leads
                SET status = ?
                WHERE id = ?
            """,
                (status, lead_id),
            )

        conn.commit()
        conn.close()

    def link_findings(self, finding_id_1: str, finding_id_2: str):
        """Create a relationship between two findings"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get current related findings for both
        for finding_id, related_id in [
            (finding_id_1, finding_id_2),
            (finding_id_2, finding_id_1),
        ]:
            cursor.execute(
                "SELECT related_findings FROM findings WHERE id = ?", (finding_id,)
            )
            row = cursor.fetchone()
            if row:
                related = json.loads(row[0] or "[]")
                if related_id not in related:
                    related.append(related_id)
                    cursor.execute(
                        "UPDATE findings SET related_findings = ? WHERE id = ?",
                        (json.dumps(related), finding_id),
                    )

        conn.commit()
        conn.close()

    def get_investigation_summary(self, investigation_id: str) -> Dict[str, Any]:
        """Get comprehensive investigation summary"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get summary
        cursor.execute(
            "SELECT * FROM investigation_summary WHERE investigation_id = ?",
            (investigation_id,),
        )
        row = cursor.fetchone()

        if not row:
            conn.close()
            return {}

        # Get findings by type
        cursor.execute(
            """
            SELECT finding_type, COUNT(*), AVG(confidence)
            FROM findings
            WHERE investigation_id = ?
            GROUP BY finding_type
        """,
            (investigation_id,),
        )
        findings_by_type = {
            row[0]: {"count": row[1], "avg_confidence": row[2]}
            for row in cursor.fetchall()
        }

        # Get leads by priority
        cursor.execute(
            """
            SELECT priority, COUNT(*), SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END)
            FROM leads
            WHERE investigation_id = ?
            GROUP BY priority
        """,
            (investigation_id,),
        )
        leads_by_priority = {
            row[0]: {"total": row[1], "completed": row[2]} for row in cursor.fetchall()
        }

        conn.close()

        summary = {
            "investigation_id": row[0],
            "name": row[1],
            "created_at": row[2],
            "updated_at": row[3],
            "total_findings": row[4],
            "total_leads": row[5],
            "status": row[6],
            "key_discoveries": json.loads(row[7] or "[]"),
            "timeline": json.loads(row[8] or "[]"),
            "findings_by_type": findings_by_type,
            "leads_by_priority": leads_by_priority,
        }

        return summary

    def add_timeline_event(
        self, investigation_id: str, event: str, details: Optional[str] = None
    ):
        """Add an event to the investigation timeline"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT timeline FROM investigation_summary WHERE investigation_id = ?",
            (investigation_id,),
        )
        row = cursor.fetchone()

        if row:
            timeline = json.loads(row[0] or "[]")
            timeline.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "event": event,
                    "details": details,
                }
            )

            cursor.execute(
                "UPDATE investigation_summary SET timeline = ?, updated_at = ? WHERE investigation_id = ?",
                (json.dumps(timeline), datetime.now().isoformat(), investigation_id),
            )
            conn.commit()

        conn.close()

    def generate_findings_report(self, investigation_id: str) -> Dict[str, Any]:
        """Generate a comprehensive findings report"""
        summary = self.get_investigation_summary(investigation_id)
        findings = self.get_all_findings(investigation_id)
        leads = self.get_all_leads(investigation_id)

        # Group findings by type
        findings_grouped = defaultdict(list)
        for finding in findings:
            findings_grouped[finding.finding_type].append(
                {
                    "value": finding.value,
                    "source": finding.source_module,
                    "confidence": finding.confidence,
                    "discovered_at": finding.discovered_at,
                    "notes": finding.notes,
                }
            )

        # High-priority pending leads
        high_priority_leads = [
            {
                "target": lead.target,
                "type": lead.target_type,
                "reason": lead.reason,
                "modules": lead.suggested_modules,
                "estimated_value": lead.estimated_value,
            }
            for lead in leads
            if lead.priority in ["critical", "high"] and lead.status == "pending"
        ]

        report = {
            "investigation_summary": summary,
            "findings_by_type": dict(findings_grouped),
            "total_findings": len(findings),
            "high_priority_leads": high_priority_leads,
            "completion_percentage": self._calculate_completion(summary, leads),
            "generated_at": datetime.now().isoformat(),
        }

        return report

    def _calculate_completion(
        self, summary: Dict[str, Any], leads: List[InvestigationLead]
    ) -> float:
        """Calculate investigation completion percentage"""
        if not leads:
            return 100.0

        completed_leads = sum(1 for lead in leads if lead.status == "completed")
        return (completed_leads / len(leads)) * 100

    def export_investigation(
        self, investigation_id: str, format: str = "json"
    ) -> Optional[str]:
        """Export complete investigation data"""
        report = self.generate_findings_report(investigation_id)

        export_dir = self.storage_path / "exports"
        export_dir.mkdir(exist_ok=True)

        if format == "json":
            filename = f"investigation_{investigation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = export_dir / filename

            with open(filepath, "w") as f:
                json.dump(report, f, indent=2, default=str)

            return str(filepath)

        elif format == "markdown":
            filename = f"investigation_{investigation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            filepath = export_dir / filename

            with open(filepath, "w") as f:
                f.write(
                    f"# Investigation Report: {report['investigation_summary']['name']}\n\n"
                )
                f.write(f"**Generated:** {report['generated_at']}\n\n")
                f.write("## Summary\n\n")
                f.write(f"- Total Findings: {report['total_findings']}\n")
                f.write(f"- Completion: {report['completion_percentage']:.1f}%\n\n")

                f.write("## Findings by Type\n\n")
                for finding_type, findings_list in report["findings_by_type"].items():
                    f.write(f"### {finding_type.title()} ({len(findings_list)})\n\n")
                    for finding in findings_list[:10]:  # Top 10
                        f.write(
                            f"- **{finding['value']}** (Source: {finding['source']}, Confidence: {finding['confidence']:.2f})\n"
                        )
                    f.write("\n")

                f.write("## High Priority Leads\n\n")
                for lead in report["high_priority_leads"]:
                    f.write(f"### {lead['target']} ({lead['type']})\n")
                    f.write(f"- **Reason:** {lead['reason']}\n")
                    f.write(f"- **Suggested Modules:** {', '.join(lead['modules'])}\n")
                    f.write(f"- **Value:** {lead['estimated_value']}\n\n")

            return str(filepath)

        return None


# Singleton instance
_tracker_instance = None


def get_investigation_tracker() -> InvestigationTracker:
    """Get or create singleton instance of investigation tracker"""
    global _tracker_instance
    if _tracker_instance is None:
        _tracker_instance = InvestigationTracker()
    return _tracker_instance
