import pytest
import datetime
import uuid
from backend.app.db.models import SecurityEvent, DetectionAlert
from backend.app.engines.readiness_engine import readiness_engine
from backend.app.engines.mitre_engine import mitre_engine
from backend.app.engines.detection_engine import detection_engine
from backend.app.engines.prioritization_engine import prioritization_engine
from backend.app.engines.vault_engine import vault_engine
from backend.app.engines.investigation_engine import investigation_engine
from backend.app.engines.evaluation_engine import evaluation_engine

@pytest.mark.asyncio
async def test_forensic_readiness_calculation(test_db):
    assessment = await readiness_engine.calculate_readiness(test_db)
    assert "score" in assessment
    assert 0.0 <= assessment["score"] <= 100.0
    assert assessment["category"] in ["FORENSICALLY RESILIENT", "MODERATE READINESS", "DEFICIENT READINESS", "CRITICAL EVIDENCE BLINDSPOT"]
    assert len(assessment["sources"]) > 0
    assert "gaps" in assessment
    
    # Test status update
    updated = await readiness_engine.update_source_status(test_db, "audit_logs", "collected", "Auditd logs acquired")
    assert updated.status == "collected"
    assert updated.readiness_factor == 0.85
    
    # Score should increase after collecting a previously missing high-weight source
    new_assessment = await readiness_engine.calculate_readiness(test_db)
    assert new_assessment["score"] > assessment["score"]

@pytest.mark.asyncio
async def test_readiness_recommendation_impact_uses_final_total_weight(test_db):
    """Regression: impact % must divide by the FINAL Σ(wᵢ), not a partial
    running total, so it is independent of source iteration order."""
    for ctx in (None, "T1110"):
        assessment = await readiness_engine.calculate_readiness(test_db, threat_context=ctx)
        total_weight = sum(s["weight"] for s in assessment["sources"])
        assert assessment["total_weight"] == round(total_weight, 3)

        # Core formula is unchanged: 100 × Σ(wᵢ×sᵢ) / Σ(wᵢ)
        weighted_sum = sum(s["weight"] * s["factor"] for s in assessment["sources"])
        assert assessment["score"] == round(100.0 * weighted_sum / total_weight, 1)

        gaps_by_name = {g["source_name"]: g for g in assessment["gaps"]}
        assert len(assessment["recommendations"]) == len(gaps_by_name) > 0
        for rec in assessment["recommendations"]:
            gap = gaps_by_name[rec["source"]]
            expected = round(gap["weight"] * (1.0 - gap["current_factor"]) / total_weight * 100, 1)
            assert rec["impact"] == f"+{expected}% potential readiness increase"

        # Closing every gap fully should account for exactly the missing score
        # (within rounding), which only holds when all impacts share one denominator.
        total_gap_impact = sum(
            g["weight"] * (1.0 - g["current_factor"]) / total_weight * 100 for g in assessment["gaps"]
        )
        non_gap_shortfall = sum(
            s["weight"] * (1.0 - s["factor"]) / total_weight * 100
            for s in assessment["sources"] if s["factor"] >= 0.85
        )
        assert abs((assessment["score"] + total_gap_impact + non_gap_shortfall) - 100.0) < 0.2

@pytest.mark.asyncio
async def test_readiness_threat_context_boost(test_db):
    baseline = await readiness_engine.calculate_readiness(test_db)
    boosted = await readiness_engine.calculate_readiness(test_db, threat_context="T1110")
    assert baseline["threat_context"] == "Normal Baseline"
    assert boosted["threat_context"] == "T1110"
    base_w = {s["source_key"]: s["weight"] for s in baseline["sources"]}
    boost_w = {s["source_key"]: s["weight"] for s in boosted["sources"]}
    for key in ("ssh_auth", "user_session", "network_conn"):
        assert boost_w[key] == min(1.0, base_w[key] * 1.15)
    assert boost_w["audit_logs"] == base_w["audit_logs"]

@pytest.mark.asyncio
async def test_mitre_attack_engine():
    tech = mitre_engine.get_technique("T1110")
    assert tech is not None
    assert tech["name"] == "Brute Force"
    assert "Credential Access" in tech["tactics"]
    
    mapping = mitre_engine.map_detection_to_technique(
        rule_id="RULE-SSH-BRUTEFORCE",
        event_type="ssh_auth_failure",
        details={"count": 5, "target_user": "ubuntu", "is_single_account": True}
    )
    assert mapping["technique_id"] == "T1110"
    assert mapping["subtechnique_id"] == "T1110.001"
    assert "Password Guessing" in mapping["mapping_rationale"] or "T1110" in mapping["mapping_rationale"]

@pytest.mark.asyncio
async def test_detection_engine_ssh_bruteforce(test_db):
    now = datetime.datetime.utcnow()
    # Insert 3 failed SSH attempts for same host within 30 seconds
    for i in range(3):
        evt = SecurityEvent(
            event_id=f"EVT-TEST-{i}",
            host="ubuntu-vm",
            timestamp=now + datetime.timedelta(seconds=i * 5),
            source="auth.log",
            event_type="ssh_auth_failure",
            user="testuser",
            source_ip="192.168.56.101",
            message=f"Failed password for testuser from 192.168.56.101 port 4820{i} ssh2",
            raw_log=f"sshd: Failed password for testuser from 192.168.56.101 port 4820{i}",
            sha256=f"hash-test-{i}-{uuid.uuid4().hex}"
        )
        test_db.add(evt)
        await test_db.commit()
        
        alerts = await detection_engine.evaluate_event(test_db, evt)
        if i < 2:
            assert len(alerts) == 0
        else:
            assert len(alerts) == 1
            alert = alerts[0]
            assert alert.rule_id == "RULE-SSH-BRUTEFORCE"
            assert alert.technique_id == "T1110"
            assert alert.severity == "HIGH"
            assert alert.event_count >= 3

@pytest.mark.asyncio
async def test_prioritization_five_strategies(test_db):
    strategies = ["static", "random", "threat_agnostic", "frozen_context", "adaptive"]
    for strat in strategies:
        res = await prioritization_engine.prioritize(
            test_db,
            strategy=strat,
            budget=50.0,
            threat_context="T1110",
            initial_threat_context="BASELINE"
        )
        assert res["strategy"] == strat
        assert res["budget_used"] <= 50.0
        assert res["remaining_budget"] >= 0.0
        assert len(res["selected_sources"]) > 0
        assert "recall" in res["metrics"]
        assert "precision" in res["metrics"]

    # Comparison endpoint logic
    comparison = await prioritization_engine.compare_all_strategies(test_db, budget=50.0, threat_context="T1110")
    assert len(comparison["strategies_comparison"]) == 5

@pytest.mark.asyncio
async def test_vault_engine_sha256_preservation(test_db, tmp_path):
    # Setup temporary vault engine pointing to tmp_path
    temp_vault = vault_engine
    temp_vault.vault_dir = tmp_path

    # Create dummy events
    evt = SecurityEvent(
        event_id="EVT-VAULT-1",
        host="ubuntu-vm",
        timestamp=datetime.datetime.utcnow(),
        source="auth.log",
        event_type="ssh_auth_failure",
        user="attacker",
        source_ip="192.168.56.101",
        message="Failed password for attacker",
        raw_log="Feb 26 12:00:00 ubuntu-vm sshd[1234]: Failed password for attacker",
        sha256="vault-dummy-hash-1"
    )
    test_db.add(evt)
    await test_db.commit()

    case_id = "CASE-TEST-001"
    vault_item = await temp_vault.acquire_evidence_from_events(
        test_db,
        case_id=case_id,
        source_key="ssh_auth",
        source_title="SSH Authentication Logs",
        event_ids=["EVT-VAULT-1"],
        original_source_path="/var/log/auth.log"
    )

    assert vault_item.evidence_id.startswith("EVD-")
    assert len(vault_item.sha256_hash) == 64
    assert vault_item.integrity_status == "VERIFIED"

    # Verify integrity
    verif = await temp_vault.verify_evidence_integrity(test_db, vault_item.evidence_id)
    assert verif["verified"] is True
    assert verif["status"] == "VERIFIED"

@pytest.mark.asyncio
async def test_investigation_and_pdf_generation(test_db):
    alert = DetectionAlert(
        alert_id="ALT-INV-1",
        rule_id="RULE-SSH-BRUTEFORCE",
        rule_name="Repeated SSH Authentication Failures",
        severity="HIGH",
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        explanation="3 failed logins detected in 60s",
        rationale="Mapping rationale for T1110",
        event_count=3,
        first_event_at=datetime.datetime.utcnow(),
        last_event_at=datetime.datetime.utcnow(),
        source_host="ubuntu-vm",
        source_ip="192.168.56.101",
        target_user="ubuntu",
        supporting_event_ids=[],
        status="ACTIVE"
    )
    test_db.add(alert)
    await test_db.commit()

    case = await investigation_engine.create_or_update_case_for_alert(test_db, alert)
    assert case.case_id.startswith("CASE-")
    assert case.primary_technique == "T1110"

    # Generate JSON report
    json_report = await investigation_engine.generate_json_report(test_db, case.case_id)
    assert json_report["case_information"]["case_id"] == case.case_id
    assert "forensic_readiness_assessment" in json_report

    # Generate PDF report
    pdf_bytes = await investigation_engine.generate_pdf_report(test_db, case.case_id)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 1000

def test_offline_research_evaluation():
    exp = evaluation_engine.run_budget_experiments(budget_levels=[20.0, 40.0])
    assert len(exp["eval_matrix"]) == 10  # 2 budgets * 5 strategies
    shift = evaluation_engine.run_context_shift_experiment()
    assert len(shift["shift_data"]) == 10  # 2 phases * 5 strategies
