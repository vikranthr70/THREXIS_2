import uuid
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from backend.app.db.models import SecurityEvent, DetectionAlert
from backend.app.core.config import settings
from backend.app.engines.mitre_engine import mitre_engine

class DetectionEngine:
    def __init__(self):
        self.rules = [
            {
                "rule_id": "RULE-SSH-BRUTEFORCE",
                "name": "Repeated SSH Authentication Failures",
                "threshold": settings.SSH_FAILURE_THRESHOLD,
                "window_seconds": settings.SSH_FAILURE_WINDOW_SECONDS,
                "severity": "HIGH",
                "enabled": True
            },
            {
                "rule_id": "RULE-SUDO-ABUSE",
                "name": "Suspicious Privilege Escalation / Sudo Failure",
                "threshold": 2,
                "window_seconds": 120,
                "severity": "HIGH",
                "enabled": True
            },
            {
                "rule_id": "RULE-ROOT-AUTH-ATTEMPT",
                "name": "Direct Root Authentication Attempt",
                "threshold": 1,
                "window_seconds": 60,
                "severity": "CRITICAL",
                "enabled": True
            }
        ]

    async def evaluate_event(self, db: AsyncSession, new_event: SecurityEvent) -> List[DetectionAlert]:
        """
        Evaluates new security events against deterministic detection rules.
        Correlates within configurable time windows.
        """
        generated_alerts: List[DetectionAlert] = []

        # Rule 1: SSH Authentication Failure burst (T1110)
        if new_event.event_type == "ssh_auth_failure":
            window_start = new_event.timestamp - datetime.timedelta(seconds=settings.SSH_FAILURE_WINDOW_SECONDS)
            
            # Query recent failure events matching host and source_ip (or user)
            query = select(SecurityEvent).where(
                and_(
                    SecurityEvent.event_type == "ssh_auth_failure",
                    SecurityEvent.host == new_event.host,
                    SecurityEvent.timestamp >= window_start,
                    SecurityEvent.timestamp <= new_event.timestamp
                )
            ).order_by(SecurityEvent.timestamp.asc())
            
            result = await db.execute(query)
            matching_events = result.scalars().all()
            
            if len(matching_events) >= settings.SSH_FAILURE_THRESHOLD:
                # Check if we already alerted on this exact recent cluster to avoid duplicate alerts
                recent_alert_query = select(DetectionAlert).where(
                    and_(
                        DetectionAlert.rule_id == "RULE-SSH-BRUTEFORCE",
                        DetectionAlert.source_host == new_event.host,
                        DetectionAlert.status != "CLOSED",
                        DetectionAlert.last_event_at >= window_start
                    )
                )
                existing_alert = (await db.execute(recent_alert_query)).scalars().first()
                
                distinct_users = list(set([e.user for e in matching_events if e.user]))
                is_single_account = len(distinct_users) <= 1
                target_user = distinct_users[0] if distinct_users else "unknown"
                src_ips = list(set([e.source_ip for e in matching_events if e.source_ip]))
                primary_ip = src_ips[0] if src_ips else "127.0.0.1"

                mapping = mitre_engine.map_detection_to_technique(
                    rule_id="RULE-SSH-BRUTEFORCE",
                    event_type="ssh_auth_failure",
                    details={
                        "count": len(matching_events),
                        "target_user": target_user,
                        "is_single_account": is_single_account
                    }
                )

                supporting_event_ids = [e.event_id for e in matching_events]
                explanation = (
                    f"Detected {len(matching_events)} failed SSH authentication attempts within "
                    f"{settings.SSH_FAILURE_WINDOW_SECONDS} seconds against host '{new_event.host}' "
                    f"targeting user '{target_user}' from IP '{primary_ip}'."
                )

                if existing_alert:
                    # Update existing active alert with latest count and supporting events
                    existing_alert.event_count = len(matching_events)
                    existing_alert.last_event_at = new_event.timestamp
                    existing_alert.supporting_event_ids = supporting_event_ids
                    existing_alert.explanation = explanation
                    await db.commit()
                    await db.refresh(existing_alert)
                    generated_alerts.append(existing_alert)
                else:
                    new_alert = DetectionAlert(
                        alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="RULE-SSH-BRUTEFORCE",
                        rule_name="Repeated SSH Authentication Failures",
                        severity="HIGH",
                        technique_id=mapping["technique_id"],
                        technique_name=mapping["technique_name"],
                        tactic=mapping["tactics"][0] if mapping["tactics"] else "Credential Access",
                        explanation=explanation,
                        rationale=mapping["mapping_rationale"],
                        event_count=len(matching_events),
                        first_event_at=matching_events[0].timestamp,
                        last_event_at=new_event.timestamp,
                        source_host=new_event.host,
                        source_ip=primary_ip,
                        target_user=target_user,
                        supporting_event_ids=supporting_event_ids,
                        status="ACTIVE"
                    )
                    db.add(new_alert)
                    await db.commit()
                    await db.refresh(new_alert)
                    generated_alerts.append(new_alert)

        # Rule 2: Root Login Attempt Check
        if new_event.user == "root" and new_event.event_type == "ssh_auth_failure":
            root_alert_id = f"ALT-ROOT-{uuid.uuid4().hex[:6].upper()}"
            # Check if root alert exists in last 60s
            recent_root = (await db.execute(select(DetectionAlert).where(
                and_(
                    DetectionAlert.rule_id == "RULE-ROOT-AUTH-ATTEMPT",
                    DetectionAlert.source_host == new_event.host,
                    DetectionAlert.status != "CLOSED",
                    DetectionAlert.last_event_at >= new_event.timestamp - datetime.timedelta(seconds=60)
                )
            ))).scalars().first()
            
            if not recent_root:
                root_alert = DetectionAlert(
                    alert_id=root_alert_id,
                    rule_id="RULE-ROOT-AUTH-ATTEMPT",
                    rule_name="Direct Root Authentication Attempt",
                    severity="CRITICAL",
                    technique_id="T1078.003",
                    technique_name="Valid Accounts: Local Accounts",
                    tactic="Initial Access",
                    explanation=f"Authentication attempt observed targeting privileged 'root' account from {new_event.source_ip or 'unknown IP'}.",
                    rationale="Direct SSH authentication attempts against root violate baseline principle of least privilege.",
                    event_count=1,
                    first_event_at=new_event.timestamp,
                    last_event_at=new_event.timestamp,
                    source_host=new_event.host,
                    source_ip=new_event.source_ip,
                    target_user="root",
                    supporting_event_ids=[new_event.event_id],
                    status="ACTIVE"
                )
                db.add(root_alert)
                await db.commit()
                await db.refresh(root_alert)
                generated_alerts.append(root_alert)

        return generated_alerts

detection_engine = DetectionEngine()
