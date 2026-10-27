from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class TelemetryEventInput(BaseModel):
    event_id: Optional[str] = None
    host: str = Field(..., json_schema_extra={"example": "ubuntu-vm"})
    timestamp: Optional[datetime] = None
    source: str = Field(..., json_schema_extra={"example": "auth.log"})
    event_type: str = Field(..., json_schema_extra={"example": "ssh_auth_failure"})
    user: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    pid: Optional[int] = None
    message: str
    raw_log: str

class TelemetryBatchInput(BaseModel):
    collector_id: str
    events: List[TelemetryEventInput]
    batch_timestamp: Optional[datetime] = None

class HeartbeatInput(BaseModel):
    host_id: str
    hostname: str
    ip_address: str
    collector_version: str
    os_info: str
    events_transmitted: int

class UpdateSourceStatusInput(BaseModel):
    source_key: str
    status: str  # unknown, missing, unavailable, available, collected, validated, not_applicable
    details: Optional[str] = None

class PrioritizeRequest(BaseModel):
    strategy: str = "adaptive"  # adaptive, static, random, threat_agnostic, frozen_context
    budget: float = 60.0
    threat_context: Optional[str] = "T1110"

class UpdateInvestigationCaseInput(BaseModel):
    analyst_notes: Optional[str] = None
    status: Optional[str] = None

class AcquireEvidenceInput(BaseModel):
    case_id: str
    source_key: str
    source_title: str
    event_ids: List[str]
    original_source_path: str = "/var/log/auth.log"

class AcquireSelectionInput(BaseModel):
    """Preserve a prioritized evidence selection for a case.

    Pass source_keys to preserve exactly what the analyst saw selected on the
    Prioritization page. Omit it to let the server run adaptive prioritization
    with the given budget/threat context and preserve that selection.
    """
    case_id: str
    source_keys: Optional[List[str]] = None
    budget: Optional[float] = None
    threat_context: Optional[str] = None
