from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.db.session import get_db
from sqlalchemy import select
from backend.app.schemas.api_schemas import AcquireEvidenceInput, AcquireSelectionInput
from backend.app.db.models import EvidenceSourceStatus, InvestigationCase, SecurityEvent
from backend.app.core.config import settings
from backend.app.core.threat_model import SOURCE_TELEMETRY
from backend.app.engines.prioritization_engine import prioritization_engine
from backend.app.engines.vault_engine import vault_engine
from backend.app.engines.readiness_engine import readiness_engine
from backend.app.core.events import manager

router = APIRouter()

@router.get("/vault/items")
async def get_vault_items(
    case_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    items = await vault_engine.get_all_vault_items(db, case_id=case_id)
    return items

@router.post("/vault/acquire")
async def acquire_evidence(
    payload: AcquireEvidenceInput,
    db: AsyncSession = Depends(get_db)
):
    """
    Acquires evidence from normalized security events, preserves raw records as an immutable file,
    computes SHA-256, generates a tamper-evident manifest, and registers the evidence in the vault.
    Also updates evidence source status in the readiness engine to 'collected'.
    """
    vault_item = await vault_engine.acquire_evidence_from_events(
        db=db,
        case_id=payload.case_id,
        source_key=payload.source_key,
        source_title=payload.source_title,
        event_ids=payload.event_ids,
        original_source_path=payload.original_source_path
    )

    # Mark source as collected
    await readiness_engine.update_source_status(
        db=db,
        source_key=payload.source_key,
        new_status="collected",
        details=f"Acquired into vault as {vault_item.evidence_id}. SHA-256: {vault_item.sha256_hash[:16]}..."
    )

    # Broadcast evidence preserved event
    await manager.broadcast({
        "type": "EVIDENCE_PRESERVED",
        "evidence_id": vault_item.evidence_id,
        "case_id": vault_item.case_id,
        "source_title": vault_item.source_title,
        "sha256": vault_item.sha256_hash,
        "record_count": vault_item.record_count
    })

    return vault_item

NON_ACQUIRABLE_STATUSES = {"missing", "unavailable", "unknown", "not_applicable"}

@router.post("/vault/acquire-selection")
async def acquire_prioritized_selection(
    payload: AcquireSelectionInput,
    db: AsyncSession = Depends(get_db)
):
    """
    Preserves a prioritized evidence selection for a case.

    For each selected source, in priority order:
      * sources missing/unavailable on the host are skipped (nothing exists to preserve);
      * sources the THREXIS collector does not stream are skipped and flagged for
        host-side acquisition (no empty or fabricated evidence files are created);
      * sources backed by collector telemetry are preserved as their own vault item
        (SHA-256 + manifest) and marked 'collected' in the readiness engine.
    """
    case = (await db.execute(
        select(InvestigationCase).where(InvestigationCase.case_id == payload.case_id)
    )).scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {payload.case_id} not found")

    selection_run = None
    source_keys = payload.source_keys
    if not source_keys:
        threat_context = payload.threat_context or case.primary_technique
        selection_run = await prioritization_engine.prioritize(
            db=db,
            strategy="adaptive",
            budget=payload.budget or settings.DEFAULT_EVIDENCE_BUDGET,
            threat_context=threat_context,
            initial_threat_context="BASELINE"
        )
        source_keys = [s["source_key"] for s in selection_run["selected_sources"]]

    sources = {
        s.source_key: s for s in (await db.execute(select(EvidenceSourceStatus))).scalars().all()
    }

    acquired, skipped = [], []
    for key in source_keys:
        src = sources.get(key)
        if src is None:
            skipped.append({"source_key": key, "source_name": key, "reason": "Unknown evidence source."})
            continue
        if src.status in NON_ACQUIRABLE_STATUSES:
            skipped.append({
                "source_key": key, "source_name": src.source_name,
                "reason": f"Source is '{src.status}' on the host, so there is nothing to preserve. Remediation: {src.remediation_action}"
            })
            continue
        telemetry = SOURCE_TELEMETRY.get(key)
        if telemetry is None:
            skipped.append({
                "source_key": key, "source_name": src.source_name,
                "reason": "Not streamed by the THREXIS collector; requires host-side acquisition."
            })
            continue

        events = (await db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.event_type.in_(telemetry["event_types"]))
            .order_by(SecurityEvent.timestamp.asc())
        )).scalars().all()
        if not events:
            skipped.append({
                "source_key": key, "source_name": src.source_name,
                "reason": f"No {' / '.join(telemetry['event_types'])} telemetry received yet."
            })
            continue

        item = await vault_engine.acquire_evidence_from_events(
            db=db,
            case_id=payload.case_id,
            source_key=key,
            source_title=src.source_name,
            event_ids=[e.event_id for e in events],
            original_source_path=telemetry["original_path"]
        )
        await readiness_engine.update_source_status(
            db=db,
            source_key=key,
            new_status="collected",
            details=f"Acquired into vault as {item.evidence_id}. SHA-256: {item.sha256_hash[:16]}..."
        )
        await manager.broadcast({
            "type": "EVIDENCE_PRESERVED",
            "evidence_id": item.evidence_id,
            "case_id": item.case_id,
            "source_title": item.source_title,
            "sha256": item.sha256_hash,
            "record_count": item.record_count
        })
        acquired.append({
            "evidence_id": item.evidence_id,
            "source_key": key,
            "source_name": src.source_name,
            "record_count": item.record_count,
            "sha256_hash": item.sha256_hash
        })

    return {
        "case_id": payload.case_id,
        "selection": {
            "origin": "server_adaptive" if selection_run else "client_selection",
            "run_id": selection_run["run_id"] if selection_run else None,
            "budget": selection_run["budget_limit"] if selection_run else None,
            "threat_context": selection_run["threat_context"] if selection_run else None,
            "source_keys": source_keys
        },
        "acquired": acquired,
        "skipped": skipped
    }

@router.post("/vault/verify/{evidence_id}")
async def verify_evidence_integrity(
    evidence_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Runs cryptographic SHA-256 integrity check against the preserved file on disk.
    Updates the custody chain manifest.
    """
    result = await vault_engine.verify_evidence_integrity(db, evidence_id)
    if result.get("status") == "ERROR":
        raise HTTPException(status_code=404, detail=result.get("message"))
    
    # If verified, we can also advance source status to 'validated' in readiness engine!
    if result.get("verified"):
        # Fetch item to get source_key
        items = await vault_engine.get_all_vault_items(db)
        match = next((i for i in items if i.evidence_id == evidence_id), None)
        if match:
            await readiness_engine.update_source_status(
                db=db,
                source_key=match.source_key,
                new_status="validated",
                details=f"Cryptographically verified SHA-256 hash {result['calculated_sha256'][:16]}..."
            )

    return result
