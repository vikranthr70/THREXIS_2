"""
Single threat model shared by the readiness and prioritization engines.

Previously the two engines encoded threat relevance independently:
readiness hardcoded a x1.15 boost for three sources when threat_context == "T1110",
while prioritization had its own technique -> source affinity matrix. They could
silently disagree. Both now derive their threat behaviour from THREAT_AFFINITY_MATRIX.
"""
from typing import Dict, List, Optional

# MITRE ATT&CK technique -> evidence source affinity in [0.0, 1.0]:
# how relevant each evidence source is to investigating that technique.
THREAT_AFFINITY_MATRIX: Dict[str, Dict[str, float]] = {
    "T1110": {  # Brute Force
        "ssh_auth": 1.00,
        "user_session": 0.90,
        "network_conn": 0.85,
        "system_journal": 0.70,
        "audit_logs": 0.80,
        "sys_config": 0.40,
        "priv_esc": 0.30,
        "process_exec": 0.35,
        "file_mod": 0.20
    },
    "T1548.003": {  # Sudo Abuse
        "priv_esc": 1.00,
        "audit_logs": 0.95,
        "system_journal": 0.85,
        "process_exec": 0.80,
        "file_mod": 0.75,
        "user_session": 0.60,
        "ssh_auth": 0.50,
        "sys_config": 0.50,
        "network_conn": 0.20
    },
    "T1059.004": {  # Unix Shell
        "process_exec": 1.00,
        "audit_logs": 0.95,
        "system_journal": 0.85,
        "user_session": 0.70,
        "file_mod": 0.60,
        "network_conn": 0.50,
        "priv_esc": 0.40,
        "ssh_auth": 0.30,
        "sys_config": 0.30
    },
    "BASELINE": {  # Default general security readiness (no active threat)
        "ssh_auth": 0.75,
        "system_journal": 0.75,
        "audit_logs": 0.75,
        "process_exec": 0.70,
        "network_conn": 0.65,
        "user_session": 0.65,
        "priv_esc": 0.60,
        "sys_config": 0.55,
        "file_mod": 0.50
    }
}

DEFAULT_AFFINITY = 0.50

# Readiness weighting: sources whose affinity for the active technique is at least
# this threshold are treated as critical and get their weight multiplied.
# For T1110 this selects ssh_auth, user_session and network_conn -- exactly the
# three sources the original hardcoded rule boosted, so T1110 scores are unchanged.
BOOST_AFFINITY_THRESHOLD = 0.85
BOOST_MULTIPLIER = 1.15


def resolve_technique(technique: Optional[str]) -> Optional[str]:
    """Return the modeled technique for an ID (exact match, else parent technique), or None."""
    if not technique:
        return None
    if technique in THREAT_AFFINITY_MATRIX and technique != "BASELINE":
        return technique
    parent = technique.split(".")[0]
    if parent in THREAT_AFFINITY_MATRIX and parent != "BASELINE":
        return parent
    return None


def get_affinity(technique: Optional[str], source_key: str) -> float:
    """Affinity of a source for a technique; unmodeled techniques fall back to BASELINE."""
    modeled = resolve_technique(technique)
    row = THREAT_AFFINITY_MATRIX[modeled] if modeled else THREAT_AFFINITY_MATRIX["BASELINE"]
    return row.get(source_key, DEFAULT_AFFINITY)


def boosted_sources(technique: Optional[str]) -> List[str]:
    """Evidence sources whose readiness weight is boosted for the given technique."""
    modeled = resolve_technique(technique)
    if not modeled:
        return []
    row = THREAT_AFFINITY_MATRIX[modeled]
    return sorted(
        (key for key, affinity in row.items() if affinity >= BOOST_AFFINITY_THRESHOLD),
        key=lambda k: -row[k]
    )


def weight_profile(technique: Optional[str]) -> Optional[dict]:
    """Describes the readiness weight adjustment applied for a technique, or None for baseline."""
    sources = boosted_sources(technique)
    if not sources:
        return None
    return {
        "technique": resolve_technique(technique),
        "boosted_sources": sources,
        "multiplier": BOOST_MULTIPLIER,
        "affinity_threshold": BOOST_AFFINITY_THRESHOLD
    }


# ---------------------------------------------------------------------------
# What the THREXIS collector actually streams, per evidence source.
# The collector (collector/threxis_collector.py) only emits these event types,
# so only these sources can be preserved in the vault from THREXIS telemetry.
# Every other source exists (or not) on the host and needs host-side acquisition.
# ---------------------------------------------------------------------------
SOURCE_TELEMETRY: Dict[str, dict] = {
    "ssh_auth": {
        "event_types": ["ssh_auth_failure", "ssh_auth_success"],
        "original_path": "/var/log/auth.log"
    },
    "priv_esc": {
        "event_types": ["sudo_event"],
        "original_path": "/var/log/auth.log (sudo)"
    }
}
