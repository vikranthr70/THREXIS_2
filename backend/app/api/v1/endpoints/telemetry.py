import uuid
import hashlib
import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, or_
from backend.app.db.session import get_db
from backend.app.db.models import SecurityEvent, CollectorHeartbeat
from backend.app.schemas.api_schemas import TelemetryBatchInput, HeartbeatInput
from backend.app.core.config import settings
from backend.app.core.events import manager
from backend.app.engines.detection_engine import detection_engine
from backend.app.engines.investigation_engine import investigation_engine
from backend.app.engines.readiness_engine import readiness_engine

router = APIRouter()

@router.post("/telemetry/ingest")
async def ingest_telemetry(
    payload: TelemetryBatchInput,
    x_collector_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
):
    """
    Ingests security event telemetry transmitted from Ubuntu VM collector.
    Deduplicates events via SHA-256 hash. Runs detection and updates investigation.
    """
    # Authenticate collector
    if x_collector_key and x_collector_key != settings.SECRET_COLLECTOR_KEY:
        raise HTTPException(status_code=401, detail="Invalid collector authentication key")

    ingested_events: List[SecurityEvent] = []
    generated_alerts = []

    for item in payload.events:
        ts = item.timestamp or datetime.datetime.now(datetime.timezone.utc)
        # Compute SHA-256 hash for deduplication and cryptographic provenance
        raw_to_hash = f"{item.host}:{ts.isoformat()}:{item.source}:{item.raw_log}"
        event_hash = hashlib.sha256(raw_to_hash.encode("utf-8")).hexdigest()

        # Check deduplication
        dedup_conditions = [SecurityEvent.sha256 == event_hash]
        if item.event_id:
            dedup_conditions.append(SecurityEvent.event_id == item.event_id)
            
        existing = (await db.execute(select(SecurityEvent).where(or_(*dedup_conditions)))).scalars().first()
        if existing:
            continue

        evt = SecurityEvent(
            event_id=item.event_id or f"EVT-{uuid.uuid4().hex[:10].upper()}",
            host=item.host,
            timestamp=ts,
            source=item.source,
            event_type=item.event_type,
            user=item.user,
            source_ip=item.source_ip,
            source_port=item.source_port,
            pid=item.pid,
            message=item.message,
            raw_log=item.raw_log,
            sha256=event_hash,
            ingested_at=datetime.datetime.utcnow()
        )
        db.add(evt)
        await db.commit()
        await db.refresh(evt)
        ingested_events.append(evt)

        # Trigger detection engine evaluation
        alerts = await detection_engine.evaluate_event(db, evt)
        for alt in alerts:
            generated_alerts.append(alt)
            # Create or update investigation case
            await investigation_engine.create_or_update_case_for_alert(db, alt)

    # Successful logins don't raise alerts, but they can change a case's outcome
    # (brute force -> possible compromise), so re-evaluate open cases.
    if any(e.event_type == "ssh_auth_success" for e in ingested_events):
        await investigation_engine.refresh_open_cases(db)

    # If new events ingested, broadcast to WebSocket clients
    if ingested_events:
        await manager.broadcast({
            "type": "TELEMETRY_BATCH",
            "count": len(ingested_events),
            "events": [
                {
                    "event_id": e.event_id,
                    "host": e.host,
                    "timestamp": e.timestamp.isoformat() + "Z",
                    "event_type": e.event_type,
                    "source": e.source,
                    "user": e.user,
                    "source_ip": e.source_ip,
                    "message": e.message
                }
                for e in ingested_events
            ]
        })

    if generated_alerts:
        await manager.broadcast({
            "type": "NEW_ALERTS",
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "rule_name": a.rule_name,
                    "severity": a.severity,
                    "technique_id": a.technique_id,
                    "technique_name": a.technique_name,
                    "explanation": a.explanation,
                    "event_count": a.event_count,
                    "last_event_at": a.last_event_at.isoformat() + "Z"
                }
                for a in generated_alerts
            ]
        })

    return {
        "status": "success",
        "ingested_count": len(ingested_events),
        "alerts_triggered": len(generated_alerts)
    }

@router.get("/telemetry/events")
async def get_recent_events(
    limit: int = Query(50, le=200),
    event_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit)
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    result = await db.execute(query)
    return result.scalars().all()

@router.post("/collector/heartbeat")
async def collector_heartbeat(
    payload: HeartbeatInput,
    x_collector_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
):
    if x_collector_key and x_collector_key != settings.SECRET_COLLECTOR_KEY:
        raise HTTPException(status_code=401, detail="Invalid collector authentication key")

    result = await db.execute(select(CollectorHeartbeat).where(CollectorHeartbeat.host_id == payload.host_id))
    hb = result.scalars().first()
    now = datetime.datetime.utcnow()

    if hb:
        hb.hostname = payload.hostname
        hb.ip_address = payload.ip_address
        hb.collector_version = payload.collector_version
        hb.os_info = payload.os_info
        hb.events_transmitted = payload.events_transmitted
        hb.status = "ONLINE"
        hb.last_heartbeat_at = now
    else:
        hb = CollectorHeartbeat(
            host_id=payload.host_id,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            collector_version=payload.collector_version,
            os_info=payload.os_info,
            status="ONLINE",
            events_transmitted=payload.events_transmitted,
            last_heartbeat_at=now
        )
        db.add(hb)

    await db.commit()
    await db.refresh(hb)

    # Broadcast collector status
    await manager.broadcast({
        "type": "COLLECTOR_HEARTBEAT",
        "host_id": hb.host_id,
        "hostname": hb.hostname,
        "status": "ONLINE",
        "ip_address": hb.ip_address,
        "last_seen": now.isoformat() + "Z"
    })

    return {"status": "ACK", "timestamp": now.isoformat() + "Z"}

@router.get("/collector/status")
async def get_collector_status(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CollectorHeartbeat).order_by(desc(CollectorHeartbeat.last_heartbeat_at)))
    collectors = result.scalars().all()
    
    # Check for timeout (stale if > 45 seconds since last heartbeat)
    now = datetime.datetime.utcnow()
    status_list = []
    for c in collectors:
        diff_sec = (now - c.last_heartbeat_at).total_seconds()
        is_active = diff_sec < 45.0
        status_list.append({
            "host_id": c.host_id,
            "hostname": c.hostname,
            "ip_address": c.ip_address,
            "collector_version": c.collector_version,
            "os_info": c.os_info,
            "status": "ONLINE" if is_active else "OFFLINE",
            "events_transmitted": c.events_transmitted,
            "last_heartbeat_at": c.last_heartbeat_at.isoformat() + "Z",
            "seconds_since_last_seen": round(diff_sec, 1)
        })

    return {
        "connected_collectors_count": len([c for c in status_list if c["status"] == "ONLINE"]),
        "collectors": status_list
    }
