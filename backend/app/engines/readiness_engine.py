from typing import List, Dict, Any, Optional
import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.app.db.models import EvidenceSourceStatus, ReadinessAssessmentHistory
from backend.app.core.threat_model import BOOST_MULTIPLIER, boosted_sources, weight_profile

STATUS_FACTORS = {
    "unknown": 0.00,
    "missing": 0.00,
    "unavailable": 0.00,
    "available": 0.60,
    "collected": 0.85,
    "validated": 1.00,
    "not_applicable": None,  # Excluded from calculation
}

DEFAULT_SOURCES = [
    {
        "source_key": "ssh_auth",
        "source_name": "SSH Authentication Logs",
        "category": "Authentication",
        "threat_relevance_weight": 0.95,
        "status": "available",
        "collection_cost": 15.0,
        "details": "/var/log/auth.log monitored via telemetry stream",
        "remediation_action": "Ensure sshd log level is VERBOSE or INFO and collector offset is maintained"
    },
    {
        "source_key": "system_journal",
        "source_name": "System Journal Logs",
        "category": "Operating System",
        "threat_relevance_weight": 0.85,
        "status": "available",
        "collection_cost": 25.0,
        "details": "systemd journal active; priority-based log retention",
        "remediation_action": "Enable persistent journal storage in /var/log/journal"
    },
    {
        "source_key": "process_exec",
        "source_name": "Process Execution Logs",
        "category": "Execution",
        "threat_relevance_weight": 0.90,
        "status": "unavailable",
        "collection_cost": 30.0,
        "details": "Kernel process accounting not actively streaming",
        "remediation_action": "Configure auditd syscall rules for execve/execveat or install auditd package"
    },
    {
        "source_key": "network_conn",
        "source_name": "Network Connection Records",
        "category": "Network",
        "threat_relevance_weight": 0.80,
        "status": "available",
        "collection_cost": 20.0,
        "details": "Socket telemetry active via netstat / ss / conntrack snapshots",
        "remediation_action": "Deploy tcpdump pcap rotation or Zeek for deep packet inspection"
    },
    {
        "source_key": "user_session",
        "source_name": "User Login/Session Records",
        "category": "Identity",
        "threat_relevance_weight": 0.75,
        "status": "available",
        "collection_cost": 10.0,
        "details": "wtmp, utmp, btmp records parsed on host",
        "remediation_action": "Verify btmp file permissions and rotation cycles"
    },
    {
        "source_key": "priv_esc",
        "source_name": "Privilege Escalation Events",
        "category": "Privilege",
        "threat_relevance_weight": 0.85,
        "status": "available",
        "collection_cost": 15.0,
        "details": "sudo log stream active in auth.log",
        "remediation_action": "Enable sudo logging to dedicated logfile /var/log/sudo.log"
    },
    {
        "source_key": "file_mod",
        "source_name": "File Modification Events",
        "category": "Integrity",
        "threat_relevance_weight": 0.70,
        "status": "missing",
        "collection_cost": 25.0,
        "details": "No inotify/fsnotify file monitoring daemon currently configured on target VM",
        "remediation_action": "Deploy inotifywait or auditd watch rules on /etc, /root, and /var/log"
    },
    {
        "source_key": "audit_logs",
        "source_name": "Audit Logs (auditd)",
        "category": "Kernel Audit",
        "threat_relevance_weight": 0.95,
        "status": "missing",
        "collection_cost": 35.0,
        "details": "Linux auditd service disabled or missing configuration rules",
        "remediation_action": "Install and start auditd with rule profiling for credential access"
    },
    {
        "source_key": "sys_config",
        "source_name": "System Configuration Evidence",
        "category": "Configuration",
        "threat_relevance_weight": 0.60,
        "status": "available",
        "collection_cost": 10.0,
        "details": "OS baseline configuration files accessible (/etc/ssh/sshd_config, /etc/passwd)",
        "remediation_action": "Maintain signed configuration baselines for drift verification"
    }
]

class ForensicReadinessEngine:
    async def initialize_sources_if_empty(self, db: AsyncSession):
        result = await db.execute(select(EvidenceSourceStatus))
        existing = result.scalars().all()
        if not existing:
            for item in DEFAULT_SOURCES:
                factor = STATUS_FACTORS.get(item["status"], 0.0)
                src = EvidenceSourceStatus(
                    source_key=item["source_key"],
                    source_name=item["source_name"],
                    category=item["category"],
                    threat_relevance_weight=item["threat_relevance_weight"],
                    status=item["status"],
                    readiness_factor=factor if factor is not None else 0.0,
                    collection_cost=item["collection_cost"],
                    last_activity_at=datetime.datetime.utcnow(),
                    details=item["details"],
                    remediation_action=item["remediation_action"],
                    sample_count=0
                )
                db.add(src)
            await db.commit()

    async def get_all_sources(self, db: AsyncSession) -> List[EvidenceSourceStatus]:
        await self.initialize_sources_if_empty(db)
        result = await db.execute(select(EvidenceSourceStatus).order_by(EvidenceSourceStatus.threat_relevance_weight.desc()))
        return result.scalars().all()

    async def update_source_status(
        self,
        db: AsyncSession,
        source_key: str,
        new_status: str,
        details: Optional[str] = None
    ) -> Optional[EvidenceSourceStatus]:
        result = await db.execute(select(EvidenceSourceStatus).where(EvidenceSourceStatus.source_key == source_key))
        source = result.scalars().first()
        if not source:
            return None
        
        factor = STATUS_FACTORS.get(new_status, 0.0)
        source.status = new_status
        source.readiness_factor = factor if factor is not None else 0.0
        source.last_activity_at = datetime.datetime.utcnow()
        if details:
            source.details = details
        await db.commit()
        await db.refresh(source)
        return source

    async def calculate_readiness(self, db: AsyncSession, threat_context: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculates forensic readiness based on:
        Readiness (%) = 100 * Σ(w_i * s_i) / Σ(w_i)
        Only applicable sources are included.
        """
        sources = await self.get_all_sources(db)

        total_weighted_readiness = 0.0
        total_weight = 0.0

        # ---- Pass 1: resolve effective weight/factor for every applicable
        # source and accumulate the FINAL Σ(wᵢ) and Σ(wᵢ×sᵢ). Gap impact
        # percentages depend on the final Σ(wᵢ), so they cannot be computed
        # inside this loop (a partial running total made them order-dependent).
        boosted = set(boosted_sources(threat_context))
        applicable = []
        for src in sources:
            if src.status == "not_applicable":
                continue

            weight = src.threat_relevance_weight
            # Boost sources critical to the active technique (shared threat model;
            # for T1110 this is ssh_auth, user_session and network_conn).
            if src.source_key in boosted:
                weight = min(1.0, weight * BOOST_MULTIPLIER)

            factor = STATUS_FACTORS.get(src.status, 0.0)
            if factor is None:
                continue

            source_contribution = weight * factor
            total_weighted_readiness += source_contribution
            total_weight += weight
            applicable.append((src, weight, factor, source_contribution))

        # ---- Pass 2: build per-source output, gaps and recommendations using
        # the final Σ(wᵢ). Impact = score gain if this source reached factor 1.0:
        #   100 × wᵢ × (1 − sᵢ) / Σ(wᵢ)
        source_contributions = []
        gaps = []
        recommendations = []
        impact_denominator = total_weight if total_weight > 0 else 1.0

        for src, weight, factor, source_contribution in applicable:
            # Gaps are sources with factor < 0.85 (not yet collected or validated)
            if factor < 0.85:
                gaps.append({
                    "source_key": src.source_key,
                    "source_name": src.source_name,
                    "category": src.category,
                    "status": src.status,
                    "weight": weight,
                    "current_factor": factor,
                    "penalty": round((weight * (1.0 - factor)), 2),
                    "remediation": src.remediation_action
                })
                recommendations.append({
                    "priority": "HIGH" if weight >= 0.85 else "MEDIUM",
                    "source": src.source_name,
                    "action": src.remediation_action,
                    "impact": f"+{round((weight * (1.0 - factor) / impact_denominator) * 100, 1)}% potential readiness increase"
                })

            source_contributions.append({
                "source_key": src.source_key,
                "source_name": src.source_name,
                "category": src.category,
                "status": src.status,
                "weight": weight,
                "factor": factor,
                "weighted_score": round(source_contribution, 3),
                "collection_cost": src.collection_cost,
                "details": src.details,
                "last_activity_at": src.last_activity_at.isoformat() if src.last_activity_at else None
            })
            
        overall_score = round((100.0 * total_weighted_readiness / total_weight), 1) if total_weight > 0 else 0.0
        
        # Categorization
        if overall_score >= 80.0:
            category = "FORENSICALLY RESILIENT"
        elif overall_score >= 60.0:
            category = "MODERATE READINESS"
        elif overall_score >= 40.0:
            category = "DEFICIENT READINESS"
        else:
            category = "CRITICAL EVIDENCE BLINDSPOT"
            
        coverage_pct = round((len([s for s in sources if s.status in ["available", "collected", "validated"]]) / len(sources)) * 100, 1)

        result_payload = {
            "score": overall_score,
            "category": category,
            "weighted_sum": round(total_weighted_readiness, 3),
            "total_weight": round(total_weight, 3),
            "coverage_percentage": coverage_pct,
            "source_count": len(sources),
            "gaps_count": len(gaps),
            "formula": "Readiness (%) = 100 × Σ(wᵢ × sᵢ) / Σ(wᵢ)",
            "sources": source_contributions,
            "gaps": gaps,
            "recommendations": recommendations,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "threat_context": threat_context or "Normal Baseline",
            # Additive field: which weight adjustment was applied (None = baseline weights)
            "weight_profile": weight_profile(threat_context)
        }
        
        return result_payload

    async def record_snapshot(self, db: AsyncSession, score_data: Dict[str, Any]):
        history_entry = ReadinessAssessmentHistory(
            score=score_data["score"],
            weighted_sum=score_data["weighted_sum"],
            total_weights=score_data["total_weight"],
            coverage_percentage=score_data["coverage_percentage"],
            gaps_count=score_data["gaps_count"],
            details=score_data
        )
        db.add(history_entry)
        await db.commit()

readiness_engine = ForensicReadinessEngine()
