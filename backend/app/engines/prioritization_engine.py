import random
import uuid
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.app.db.models import EvidenceSourceStatus, PrioritizationRecord
from backend.app.core.threat_model import THREAT_AFFINITY_MATRIX, get_affinity

class EvidencePrioritizationEngine:
    def __init__(self):
        # Threat-informed relevance mapping lives in core/threat_model.py so the
        # readiness engine uses the exact same model.
        self.threat_affinity_matrix = THREAT_AFFINITY_MATRIX

    def _get_affinity(self, threat_technique: Optional[str], source_key: str) -> float:
        return get_affinity(threat_technique, source_key)

    async def prioritize(
        self,
        db: AsyncSession,
        strategy: str = "adaptive",
        budget: float = 60.0,
        threat_context: Optional[str] = "T1110",
        initial_threat_context: Optional[str] = "BASELINE"
    ) -> Dict[str, Any]:
        """
        Executes one of the 5 evaluation strategies under a specified evidence collection budget.
        
        Strategies:
        1. 'static': Pre-defined static ordering regardless of threat context.
        2. 'random': Random sampling within budget.
        3. 'threat_agnostic': Ranked strictly by availability / cost ratio without threat context.
        4. 'adaptive': Dynamic utility = (threat_affinity * threat_relevance_weight * availability_factor) / cost.
        5. 'frozen_context': Adaptive logic, but frozen on initial_threat_context (ignores shifts).
        """
        result = await db.execute(select(EvidenceSourceStatus))
        sources = result.scalars().all()

        candidate_items = []
        for src in sources:
            avail_factor = 0.60 if src.status == "available" else (0.85 if src.status == "collected" else (1.0 if src.status == "validated" else 0.05))
            candidate_items.append({
                "source_key": src.source_key,
                "source_name": src.source_name,
                "category": src.category,
                "status": src.status,
                "base_weight": src.threat_relevance_weight,
                "cost": src.collection_cost,
                "availability_factor": avail_factor,
                "remediation_action": src.remediation_action
            })

        active_strategy = strategy.lower()

        if active_strategy == "static":
            # Fixed hardcoded order: e.g. system_journal, sys_config, network_conn, process_exec, ssh_auth...
            fixed_order = ["system_journal", "sys_config", "network_conn", "process_exec", "ssh_auth", "user_session", "priv_esc", "file_mod", "audit_logs"]
            sorted_items = sorted(candidate_items, key=lambda x: fixed_order.index(x["source_key"]) if x["source_key"] in fixed_order else 99)
            for item in sorted_items:
                item["priority_score"] = round(1.0 - (fixed_order.index(item["source_key"]) * 0.1), 2) if item["source_key"] in fixed_order else 0.1
                item["rationale"] = "Static baseline ranking independent of threat telemetry."

        elif active_strategy == "random":
            shuffled = list(candidate_items)
            random.seed(42)  # reproducible random
            random.shuffle(shuffled)
            sorted_items = shuffled
            for idx, item in enumerate(sorted_items):
                item["priority_score"] = round(1.0 - (idx * 0.1), 2)
                item["rationale"] = "Stochastic baseline selection for comparison."

        elif active_strategy == "threat_agnostic":
            # Ranked strictly by availability / cost (cheap available sources first, ignoring threats)
            for item in candidate_items:
                score = (item["availability_factor"] * item["base_weight"]) / (item["cost"] / 10.0)
                item["priority_score"] = round(score, 3)
                item["rationale"] = f"Threat-agnostic cost-efficiency (avail={item['availability_factor']}, cost={item['cost']})."
            sorted_items = sorted(candidate_items, key=lambda x: x["priority_score"], reverse=True)

        elif active_strategy == "frozen_context":
            # Adaptive, but frozen to initial_threat_context (e.g. BASELINE) ignoring new threat (e.g. T1110)
            ctx = initial_threat_context or "BASELINE"
            for item in candidate_items:
                affinity = self._get_affinity(ctx, item["source_key"])
                threat_weight = item["base_weight"] * affinity
                # Threat-informed utility ratio
                utility = (threat_weight * item["availability_factor"] * 100.0) / max(item["cost"], 1.0)
                item["priority_score"] = round(utility, 3)
                item["threat_affinity"] = affinity
                item["rationale"] = f"Frozen context ({ctx}) affinity={affinity:.2f}. Stale model ignoring detected {threat_context}."
            sorted_items = sorted(candidate_items, key=lambda x: x["priority_score"], reverse=True)

        else: # "adaptive"
            # Active threat-informed utility:
            # Utility = (Threat_Affinity(T) * Base_Weight * Availability) / Acquisition_Cost
            for item in candidate_items:
                affinity = self._get_affinity(threat_context, item["source_key"])
                threat_weight = item["base_weight"] * affinity
                utility = (threat_weight * item["availability_factor"] * 100.0) / max(item["cost"], 1.0)
                item["priority_score"] = round(utility, 3)
                item["threat_affinity"] = affinity
                item["rationale"] = (
                    f"Adaptive threat-informed: Affinity={affinity:.2f} for {threat_context or 'BASELINE'}, "
                    f"availability={item['availability_factor']}, acquisition cost={item['cost']}."
                )
            sorted_items = sorted(candidate_items, key=lambda x: x["priority_score"], reverse=True)

        # Apply Knapsack / Greedy Budget Constraint
        remaining_budget = budget
        selected = []
        unselected = []
        
        for item in sorted_items:
            if item["cost"] <= remaining_budget:
                remaining_budget -= item["cost"]
                item["selected"] = True
                item["remaining_after"] = round(remaining_budget, 1)
                selected.append(item)
            else:
                item["selected"] = False
                item["remaining_after"] = round(remaining_budget, 1)
                item["rejection_reason"] = f"Exceeds remaining budget ({item['cost']} > {round(remaining_budget, 1)})"
                unselected.append(item)

        budget_used = round(budget - remaining_budget, 1)
        budget_utilization_pct = round((budget_used / budget) * 100.0, 1) if budget > 0 else 0.0

        # Calculate metrics for academic evaluation:
        # Ground-truth relevant sources for T1110 are ssh_auth, user_session, network_conn
        target_threat = threat_context or "T1110"
        relevant_keys = {"ssh_auth", "user_session", "network_conn"} if target_threat == "T1110" else {"priv_esc", "audit_logs", "system_journal"}
        selected_keys = {x["source_key"] for x in selected}
        
        true_positives = len(selected_keys.intersection(relevant_keys))
        recall = round(true_positives / len(relevant_keys), 2) if relevant_keys else 1.0
        precision = round(true_positives / len(selected_keys), 2) if selected_keys else 0.0
        cost_per_relevant = round(budget_used / max(true_positives, 1), 2)

        run_id = f"PRIO-{uuid.uuid4().hex[:8].upper()}"
        metrics = {
            "recall": recall,
            "precision": precision,
            "cost_per_relevant_item": cost_per_relevant,
            "true_positives": true_positives,
            "total_relevant": len(relevant_keys)
        }

        # Persist record
        record = PrioritizationRecord(
            run_id=run_id,
            timestamp=datetime.datetime.utcnow(),
            strategy=active_strategy,
            budget_limit=budget,
            budget_used=budget_used,
            selected_sources=selected,
            unselected_sources=unselected,
            threat_context=threat_context or "BASELINE",
            performance_metrics=metrics
        )
        db.add(record)
        await db.commit()

        return {
            "run_id": run_id,
            "timestamp": record.timestamp.isoformat() + "Z",
            "strategy": active_strategy,
            "budget_limit": budget,
            "budget_used": budget_used,
            "remaining_budget": round(remaining_budget, 1),
            "budget_utilization_pct": budget_utilization_pct,
            "threat_context": threat_context or "BASELINE",
            "ranked_items": sorted_items,
            "selected_sources": selected,
            "unselected_sources": unselected,
            "metrics": metrics
        }

    async def compare_all_strategies(
        self,
        db: AsyncSession,
        budget: float = 50.0,
        threat_context: str = "T1110"
    ) -> Dict[str, Any]:
        """
        Runs and benchmarks all 5 strategies under identical budget and threat conditions.
        """
        strategies = ["static", "random", "threat_agnostic", "frozen_context", "adaptive"]
        comparisons = []
        
        for strat in strategies:
            res = await self.prioritize(
                db=db,
                strategy=strat,
                budget=budget,
                threat_context=threat_context,
                initial_threat_context="BASELINE"
            )
            comparisons.append({
                "strategy": strat,
                "budget_used": res["budget_used"],
                "remaining_budget": res["remaining_budget"],
                "utilization_pct": res["budget_utilization_pct"],
                "selected_count": len(res["selected_sources"]),
                "selected_sources": [s["source_name"] for s in res["selected_sources"]],
                "recall": res["metrics"]["recall"],
                "precision": res["metrics"]["precision"],
                "cost_per_relevant": res["metrics"]["cost_per_relevant_item"]
            })
            
        return {
            "budget": budget,
            "threat_context": threat_context,
            "strategies_comparison": comparisons
        }

prioritization_engine = EvidencePrioritizationEngine()
