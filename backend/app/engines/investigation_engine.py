import io
import json
import uuid
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from backend.app.db.models import InvestigationCase, DetectionAlert, SecurityEvent, EvidenceVaultItem, EvidenceSourceStatus
from backend.app.core.config import settings
from backend.app.engines.readiness_engine import readiness_engine
from backend.app.engines.mitre_engine import mitre_engine

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

OPEN_CASE_STATUSES = ["ACTIVE", "UNDER_REVIEW"]
VALID_CASE_STATUSES = {"ACTIVE", "UNDER_REVIEW", "PRESERVED", "CLOSED"}
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Investigative prompts per ATT&CK technique (exact ID, then parent). These are open
# questions for the analyst, not findings, so they are phrased as questions.
TECHNIQUE_QUESTIONS = {
    "T1110": [
        "Did source IP {ips} target other hosts or accounts in the environment?",
        "Are account lockout / fail2ban controls in place on {hosts}, and did they trigger?"
    ],
    "T1078": [
        "Is direct root login over SSH permitted on {hosts} (sshd PermitRootLogin)?",
        "Are any other privileged accounts exposed to password authentication?"
    ],
    "T1548": ["Which commands were run via sudo on {hosts}, and were they authorized?"],
    "T1059": ["Which commands or scripts were executed, and from which session?"],
}


def _fmt(ts: Optional[datetime.datetime]) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "unknown time"


def _join(values) -> str:
    vals = [v for v in values if v]
    return ", ".join(sorted(set(vals))) if vals else "unknown"


class InvestigationEngine:
    async def _case_alerts(self, db: AsyncSession, case: InvestigationCase) -> List[DetectionAlert]:
        if not case.supporting_alert_ids:
            return []
        res = await db.execute(select(DetectionAlert).where(DetectionAlert.alert_id.in_(case.supporting_alert_ids)))
        return list(res.scalars().all())

    async def _find_open_case_for_alert(self, db: AsyncSession, alert: DetectionAlert) -> Optional[InvestigationCase]:
        """
        One incident = one attacker against one host. An open case is reused when any of
        its alerts shares the new alert's source host and source IP, regardless of
        ATT&CK technique (a brute force and the root-login attempts it contains belong to
        the same incident). Alerts without a source IP fall back to host + technique.
        """
        open_cases = (await db.execute(
            select(InvestigationCase)
            .where(InvestigationCase.status.in_(OPEN_CASE_STATUSES))
            .order_by(InvestigationCase.updated_at.desc())
        )).scalars().all()
        for case in open_cases:
            for a in await self._case_alerts(db, case):
                same_host = a.source_host == alert.source_host
                if alert.source_ip:
                    if same_host and a.source_ip == alert.source_ip:
                        return case
                elif same_host and case.primary_technique == alert.technique_id:
                    return case
        return None

    async def refresh_case(self, db: AsyncSession, case: InvestigationCase) -> InvestigationCase:
        """
        Regenerates title, severity, primary technique, summary, findings and open questions
        from the case's current alerts and telemetry. Nothing here is a fixed template claim:
        every finding is computed from stored data, including whether the attack succeeded.
        Analyst notes, status and readiness-at-detection are never touched.
        """
        alerts = await self._case_alerts(db, case)
        if not alerts:
            return case

        ranked = sorted(
            alerts,
            key=lambda a: (a.event_count or 0, SEVERITY_RANK.get(a.severity, 0), a.last_event_at),
            reverse=True
        )
        lead = ranked[0]
        hosts = {a.source_host for a in alerts if a.source_host}
        ips = {a.source_ip for a in alerts if a.source_ip}
        users = {a.target_user for a in alerts if a.target_user}
        first_seen = min(a.first_event_at for a in alerts)
        last_seen = max(a.last_event_at for a in alerts)
        techniques = []
        for a in ranked:
            label = f"{a.technique_id} ({a.technique_name})"
            if label not in techniques:
                techniques.append(label)

        # ---- Compromise check: did any login from the attacking IP succeed? ----
        successes: List[SecurityEvent] = []
        if ips:
            successes = list((await db.execute(
                select(SecurityEvent).where(and_(
                    SecurityEvent.event_type == "ssh_auth_success",
                    SecurityEvent.source_ip.in_(list(ips)),
                    SecurityEvent.host.in_(list(hosts)),
                    SecurityEvent.timestamp >= first_seen
                )).order_by(SecurityEvent.timestamp.asc())
            )).scalars().all())

        event_ids = list(dict.fromkeys(
            [eid for a in alerts for eid in (a.supporting_event_ids or [])] + [e.event_id for e in successes]
        ))

        severity = max((a.severity for a in alerts), key=lambda s: SEVERITY_RANK.get(s, 0))
        if successes:
            severity = "CRITICAL"

        title = f"{lead.technique_name} from {_join(ips)} on {_join(hosts)}"
        if successes:
            title = f"Possible compromise: {title}"

        summary = (
            f"{len(alerts)} detection alert{'s' if len(alerts) != 1 else ''} mapped to {', '.join(techniques)}, "
            f"with {len(event_ids)} supporting events from {_join(ips)} against account(s) {_join(users)} "
            f"on {_join(hosts)}, observed {_fmt(first_seen)} to {_fmt(last_seen)}."
        )
        if successes:
            s0 = successes[0]
            summary += (
                f" A successful SSH login for '{s0.user}' from {s0.source_ip} was recorded at "
                f"{_fmt(s0.timestamp)}; the account should be treated as compromised."
            )
        else:
            summary += " No successful SSH login from the source IP has been recorded in collected telemetry."

        findings = [
            f"{a.rule_name}: {a.event_count} event{'s' if a.event_count != 1 else ''} against "
            f"'{a.target_user or 'unknown'}' from {a.source_ip or 'unknown IP'} on {a.source_host}, "
            f"mapped to {a.technique_id} ({a.technique_name}, {a.tactic})."
            for a in ranked
        ]
        if successes:
            for e in successes:
                findings.append(
                    f"SUCCESSFUL SSH login for '{e.user}' from {e.source_ip} at {_fmt(e.timestamp)} "
                    f"after failed attempts from the same IP."
                )
        else:
            findings.append(
                f"No successful SSH login from {_join(ips)} was recorded in collected telemetry after "
                f"{_fmt(first_seen)}. This covers events streamed by the THREXIS collector only."
            )
        findings.append(f"SHA-256 integrity hashes were recorded at ingestion for all {len(event_ids)} supporting events.")

        fmt_args = {"ips": _join(ips), "hosts": _join(hosts)}
        questions: List[str] = []
        if successes:
            questions.append(
                "What did the attacker do after logging in? Review session, process and file activity on the host."
            )
        for a in ranked:
            for key in (a.technique_id, a.technique_id.split(".")[0]):
                for q in TECHNIQUE_QUESTIONS.get(key, []):
                    q = q.format(**fmt_args)
                    if q not in questions:
                        questions.append(q)

        case.title = title
        case.severity = severity
        case.primary_technique = lead.technique_id
        case.summary = summary
        case.findings = findings
        case.unresolved_questions = questions
        case.supporting_alert_ids = [a.alert_id for a in alerts]
        case.supporting_event_ids = event_ids
        case.updated_at = datetime.datetime.utcnow()
        await db.commit()
        await db.refresh(case)
        return case

    async def create_or_update_case_for_alert(
        self,
        db: AsyncSession,
        alert: DetectionAlert
    ) -> InvestigationCase:
        """
        Attaches an alert to the open case for the same attacker + host, or opens a new case.
        Case content is regenerated from real data on every update.
        """
        case = await self._find_open_case_for_alert(db, alert)

        if case is None:
            readiness_data = await readiness_engine.calculate_readiness(db, threat_context=alert.technique_id)
            case = InvestigationCase(
                case_id=f"CASE-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}",
                title=f"{alert.technique_name} on {alert.source_host}",
                status="ACTIVE",
                severity=alert.severity,
                primary_technique=alert.technique_id,
                summary="",
                scope_and_methodology=(
                    "Scope encompasses Linux authentication telemetry streamed by the THREXIS collector "
                    "(SSH authentication and sudo events). Investigation follows threat-informed digital forensic "
                    "readiness principles, prioritizing evidence acquisition under constrained budgets with "
                    "SHA-256 chain-of-custody preservation."
                ),
                analyst_notes="",
                findings=[],
                unresolved_questions=[],
                # Recorded once, when the case is opened, and never overwritten afterwards.
                readiness_score_at_time=readiness_data["score"],
                supporting_event_ids=alert.supporting_event_ids or [],
                supporting_alert_ids=[alert.alert_id]
            )
            db.add(case)
            await db.commit()
            await db.refresh(case)
        elif alert.alert_id not in (case.supporting_alert_ids or []):
            case.supporting_alert_ids = list(case.supporting_alert_ids or []) + [alert.alert_id]

        return await self.refresh_case(db, case)

    async def refresh_open_cases(self, db: AsyncSession) -> None:
        """Re-evaluates open cases, e.g. after a successful login arrives with no new alert."""
        open_cases = (await db.execute(
            select(InvestigationCase).where(InvestigationCase.status.in_(OPEN_CASE_STATUSES))
        )).scalars().all()
        for case in open_cases:
            await self.refresh_case(db, case)

    async def get_case_details(self, db: AsyncSession, case_id: str) -> Optional[Dict[str, Any]]:
        result = await db.execute(select(InvestigationCase).where(InvestigationCase.case_id == case_id))
        case = result.scalars().first()
        if not case:
            return None

        # Fetch associated alerts
        alerts_res = await db.execute(select(DetectionAlert).where(DetectionAlert.alert_id.in_(case.supporting_alert_ids or [])))
        alerts = alerts_res.scalars().all()

        # Fetch timeline events
        events_res = await db.execute(select(SecurityEvent).where(SecurityEvent.event_id.in_(case.supporting_event_ids or [])).order_by(SecurityEvent.timestamp.asc()))
        events = events_res.scalars().all()

        # Fetch associated vault items
        vault_res = await db.execute(select(EvidenceVaultItem).where(EvidenceVaultItem.case_id == case_id))
        vault_items = vault_res.scalars().all()

        tech_info = mitre_engine.get_technique(case.primary_technique) or {}

        # Construct granular timeline
        timeline = []
        for e in events:
            timeline.append({
                "id": e.event_id,
                "timestamp": e.timestamp.isoformat() + "Z",
                "type": "SECURITY_EVENT",
                "title": f"Security Event: {e.event_type}",
                "description": e.message,
                "host": e.host,
                "source": e.source,
                "user": e.user,
                "source_ip": e.source_ip,
                "sha256": e.sha256
            })
        for a in alerts:
            timeline.append({
                "id": a.alert_id,
                "timestamp": a.last_event_at.isoformat() + "Z",
                "type": "DETECTION_ALERT",
                "title": f"Detection: {a.rule_name}",
                "description": a.explanation,
                "severity": a.severity,
                "technique": f"{a.technique_id} - {a.technique_name}"
            })
        for v in vault_items:
            timeline.append({
                "id": v.evidence_id,
                "timestamp": v.acquired_at.isoformat() + "Z",
                "type": "EVIDENCE_ACQUIRED",
                "title": f"Forensic Evidence Acquired: {v.source_title}",
                "description": f"Preserved {v.record_count} items. SHA-256: {v.sha256_hash[:16]}...",
                "sha256": v.sha256_hash
            })

        timeline.sort(key=lambda x: x["timestamp"])

        return {
            "case": case,
            "alerts": alerts,
            "events_count": len(events),
            "vault_items": vault_items,
            "technique_info": tech_info,
            "timeline": timeline
        }

    async def update_notes(
        self,
        db: AsyncSession,
        case_id: str,
        notes: Optional[str] = None,
        status: Optional[str] = None
    ) -> Optional[InvestigationCase]:
        """
        Updates analyst notes and/or status. Fields left as None are not touched, so a
        status change never wipes the notes. Closing a case closes its alerts (so the
        dashboard leaves threat-adjusted mode); reopening reactivates them.
        """
        result = await db.execute(select(InvestigationCase).where(InvestigationCase.case_id == case_id))
        case = result.scalars().first()
        if not case:
            return None
        if notes is not None:
            case.analyst_notes = notes
        if status:
            status = status.upper()
            if status not in VALID_CASE_STATUSES:
                raise ValueError(f"Invalid case status '{status}'")
            if status != case.status:
                alert_status = "CLOSED" if status == "CLOSED" else "ACTIVE"
                for a in await self._case_alerts(db, case):
                    a.status = alert_status
            case.status = status
        case.updated_at = datetime.datetime.utcnow()
        await db.commit()
        await db.refresh(case)
        return case

    async def generate_json_report(self, db: AsyncSession, case_id: str) -> Dict[str, Any]:
        data = await self.get_case_details(db, case_id)
        if not data:
            return {"error": "Case not found"}
        
        case: InvestigationCase = data["case"]
        readiness_data = await readiness_engine.calculate_readiness(db, threat_context=case.primary_technique)

        report = {
            "report_metadata": {
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "system": "THREXIS Threat-Informed Adaptive Forensic Investigation System",
                "version": "1.0.0-academic",
                "case_id": case.case_id
            },
            "case_information": {
                "case_id": case.case_id,
                "title": case.title,
                "status": case.status,
                "severity": case.severity,
                "created_at": case.created_at.isoformat() + "Z",
                "updated_at": case.updated_at.isoformat() + "Z",
                "primary_technique": case.primary_technique,
                "summary": case.summary,
                "scope_and_methodology": case.scope_and_methodology
            },
            "mitre_attack_intelligence": data["technique_info"],
            "forensic_readiness_assessment": {
                "score_at_time": case.readiness_score_at_time,
                "current_score": readiness_data["score"],
                "category": readiness_data["category"],
                "formula": readiness_data["formula"],
                "gaps": readiness_data["gaps"],
                "recommendations": readiness_data["recommendations"]
            },
            "findings": case.findings,
            "unresolved_questions": case.unresolved_questions,
            "analyst_notes": case.analyst_notes,
            "evidence_inventory": [
                {
                    "evidence_id": item.evidence_id,
                    "source_title": item.source_title,
                    "original_path": item.original_source_path,
                    "record_count": item.record_count,
                    "sha256": item.sha256_hash,
                    "integrity_status": item.integrity_status,
                    "acquired_at": item.acquired_at.isoformat() + "Z"
                }
                for item in data["vault_items"]
            ],
            "timeline": data["timeline"],
            "limitations": [
                *(
                    [f"Evidence sources missing or unavailable at report time: {', '.join(g['source_name'] for g in readiness_data['gaps'] if g['current_factor'] == 0)}."]
                    if any(g["current_factor"] == 0 for g in readiness_data["gaps"]) else []
                ),
                "Telemetry covers only events streamed by the THREXIS collector (SSH authentication and sudo).",
                "Adversary intent inferred from authentication telemetry without memory or disk forensics."
            ]
        }
        return report

    async def generate_pdf_report(self, db: AsyncSession, case_id: str) -> bytes:
        data = await self.get_case_details(db, case_id)
        if not data:
            raise ValueError(f"Case {case_id} not found")
        
        case: InvestigationCase = data["case"]
        readiness_data = await readiness_engine.calculate_readiness(db, threat_context=case.primary_technique)
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=8
        )
        h2_style = ParagraphStyle(
            'H2Style',
            parent=styles['Heading2'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#0D9488'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )
        bold_style = ParagraphStyle(
            'BoldStyle',
            parent=body_style,
            fontName='Helvetica-Bold'
        )

        elements = []

        # Header
        elements.append(Paragraph("THREXIS FORENSIC INVESTIGATION REPORT", title_style))
        elements.append(Paragraph(f"<b>Case ID:</b> {case.case_id} | <b>Generated:</b> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0D9488'), spaceBefore=6, spaceAfter=12))

        # Case Summary Table
        case_info_data = [
            [Paragraph("<b>Incident Title:</b>", body_style), Paragraph(case.title, body_style)],
            [Paragraph("<b>Status:</b>", body_style), Paragraph(case.status, body_style)],
            [Paragraph("<b>Severity:</b>", body_style), Paragraph(case.severity, body_style)],
            [Paragraph("<b>Primary MITRE Technique:</b>", body_style), Paragraph(f"{case.primary_technique} - {data['technique_info'].get('name', 'N/A')}", body_style)],
            [Paragraph("<b>Forensic Readiness Score:</b>", body_style), Paragraph(f"{readiness_data['score']}% ({readiness_data['category']})", body_style)]
        ]
        t = Table(case_info_data, colWidths=[150, 380])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

        # Executive Summary
        elements.append(Paragraph("1. Executive Summary & Scope", h2_style))
        elements.append(Paragraph(case.summary, body_style))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(case.scope_and_methodology, body_style))
        elements.append(Spacer(1, 10))

        # Threat Intelligence Mapping
        elements.append(Paragraph("2. Threat Intelligence Context (MITRE ATT&CK)", h2_style))
        tech_desc = data['technique_info'].get('description', 'Standard attack telemetry pattern.')
        elements.append(Paragraph(f"<b>Technique:</b> {case.primary_technique} - {data['technique_info'].get('name', 'N/A')}", body_style))
        elements.append(Paragraph(f"<b>Tactics:</b> {', '.join(data['technique_info'].get('tactics', []))}", body_style))
        elements.append(Paragraph(f"<b>Description:</b> {tech_desc[:300]}...", body_style))
        elements.append(Spacer(1, 10))

        # Key Findings
        elements.append(Paragraph("3. Key Forensic Findings", h2_style))
        for finding in case.findings:
            elements.append(Paragraph(f"• {finding}", body_style))
        elements.append(Spacer(1, 10))

        # Preserved Evidence Vault Inventory
        elements.append(Paragraph("4. Preserved Forensic Evidence & Cryptographic Chain-of-Custody", h2_style))
        if data["vault_items"]:
            evd_table_data = [["Evidence ID", "Source Title", "Records", "SHA-256 Hash", "Status"]]
            for v in data["vault_items"]:
                evd_table_data.append([
                    Paragraph(v.evidence_id, body_style),
                    Paragraph(v.source_title, body_style),
                    str(v.record_count),
                    Paragraph(f"{v.sha256_hash[:16]}...", body_style),
                    v.integrity_status
                ])
            et = Table(evd_table_data, colWidths=[90, 110, 50, 200, 80])
            et.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0D9488')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(et)
        else:
            elements.append(Paragraph("No physical evidence records preserved in the vault for this case yet.", body_style))
        elements.append(Spacer(1, 10))

        # Investigation Chronology
        elements.append(Paragraph("5. Chronological Event Timeline", h2_style))
        timeline_rows = [["Timestamp", "Type", "Details"]]
        for t_item in data["timeline"][:10]: # Top 10 for layout
            timeline_rows.append([
                Paragraph(t_item["timestamp"][:19], body_style),
                Paragraph(t_item["type"], body_style),
                Paragraph(t_item["title"], body_style)
            ])
        tt = Table(timeline_rows, colWidths=[120, 110, 300])
        tt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(tt)
        elements.append(Spacer(1, 10))

        # Analyst Notes & Limitations
        elements.append(Paragraph("6. Analyst Notes & Investigation Limitations", h2_style))
        elements.append(Paragraph(f"<b>Analyst Notes:</b> {case.analyst_notes}", body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<b>Investigation Limitations:</b> Analysis is strictly bounded by available evidence sources. No conclusion of compromise has been made without verified telemetry confirmation.", body_style))

        doc.build(elements)
        return buffer.getvalue()

investigation_engine = InvestigationEngine()
