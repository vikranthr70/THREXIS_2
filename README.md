# THREXIS — Threat-Informed Adaptive Digital Forensic Readiness & Incident Investigation System

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg?logo=react&logoColor=black)](https://react.dev)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise-E63946.svg)](https://attack.mitre.org)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![Integrity](https://img.shields.io/badge/Integrity-SHA--256-0D9488.svg)](#evidence-vault)

---

## 1. Project Overview

**THREXIS** is an intelligent, threat-informed digital forensic readiness platform that continuously observes security events, detects suspicious activity, identifies relevant threats using **MITRE ATT&CK Enterprise**, calculates quantitative forensic readiness, dynamically prioritizes evidence collection under constrained collection budgets, and supports court-admissible incident investigation.

### Central Research Question
> **How can threat-informed adaptive evidence prioritization improve digital forensic readiness and incident investigation under limited evidence collection resources?**

### Operational Workflow
```text
Live Security Events → Threat Detection → MITRE ATT&CK Intelligence → 
Forensic Readiness Assessment → Adaptive Evidence Prioritization → 
Evidence Preservation (SHA-256) → Incident Investigation → Forensic Report (PDF & JSON)
```

---

## 2. System Architecture

```text
       Ubuntu VirtualBox VM (Host-Only Network 192.168.56.x)
                                 │
                   auth.log / journald / auditd
                                 ▼
                     THREXIS Telemetry Collector
                                 │
                   Authenticated HTTP Stream
                                 ▼
                    Windows 11 THREXIS API
                    (FastAPI + SQLite WAL)
                                 │
            ┌────────────────────┴────────────────────┐
            ▼                                         ▼
   Threat Detection Rule Engine              Forensic Readiness Engine
   (T1110, T1078, T1548.003)            Readiness (%) = 100 × Σ(wᵢ × sᵢ) / Σ(wᵢ)
            │                                         │
            └────────────────────┬────────────────────┘
                                 ▼
               Adaptive Evidence Prioritization
              (Knapsack Constrained Optimization)
           [Adaptive | Static | Random | Agnostic | Frozen]
                                 │
                                 ▼
                     Incident Investigation Case
                                 │
                                 ▼
                   Evidence Vault (SHA-256 Sealed)
                                 │
                                 ▼
                Court-Admissible Investigation Report
                           (PDF / JSON)
                                 │
                                 ▼
                 THREXIS React Workstation Dashboard
```

---

## 3. Workstation Navigation & Pages

THREXIS provides six primary sidebar sections:

1. **Command Center**:
   - Prominent segmented readiness instrument gauge.
   - Live telemetry counters, high-severity alert tracking, and Ubuntu VirtualBox VM collector health.
   - Active MITRE ATT&CK threat mapping and current incident summary.
   - Live observed event stream with inspection modal.

2. **Forensic Readiness Engine**:
   - Quantitative weighted scoring formula:
     $$\text{Readiness (\%)} = 100 \times \frac{\sum (w_i \times s_i)}{\sum w_i}$$
   - Model factors: `Available` (0.60), `Collected` (0.85), `Validated` (1.00), `Missing/Unavailable` (0.00).
   - Interactive evidence source lifecycle selector.
   - Automated gap analysis with penalty deductions and ROI remediation rankings.

3. **Threat Detection & MITRE ATT&CK Intelligence**:
   - Deterministic detection rules for SSH authentication bursts, root login attempts, and privilege escalation.
   - Transparent evidentiary rationale mapping to MITRE ATT&CK (e.g. `T1110` Brute Force and `T1110.001` Password Guessing).
   - Interactive MITRE ATT&CK Enterprise Matrix explorer.

4. **Adaptive Evidence Prioritization**:
   - Implementation and empirical comparison of 5 selection strategies:
     1. **Adaptive Threat-Informed** (dynamic utility based on technique affinity)
     2. **Static Selection** (fixed baseline order)
     3. **Random Selection** (stochastic baseline)
     4. **Threat-Agnostic** (cost-to-availability ratio only)
     5. **Frozen-Context** (stale threat prior without adaptation)
   - Interactive collection budget slider (15 to 120 units) and budget utilization metrics.
   - Real-time recall, precision, and cost-per-relevant-item benchmarking.

5. **Incident Investigation**:
   - Automatically opens and updates investigation cases (`CASE-YYYYMMDD-XXXX`).
   - Chronological event timeline synchronizing raw events, detection alerts, and vault acquisitions.
   - Forensic findings and unresolved investigative hypotheses.
   - Real-time editable analyst working notes with persistent commit.
   - Downloadable court-admissible PDF reports (ReportLab) and structured JSON exports.

6. **Forensic Evidence Vault**:
   - Bit-stream evidence preservation with immediate SHA-256 cryptographic hashing.
   - Immutable custody chain manifests (`.manifest.json`).
   - Interactive **Verify Integrity** button performing bit-level re-hashing against stored records.

---

## 4. Quickstart & Installation (Windows 11 Host)

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Windows 11 Host with Oracle VirtualBox (for live VM telemetry)

### Step 1: Set Up Python Backend
```powershell
# Navigate to project root
cd "c:\Users\Vikranth Reddy\threxis_original"

# Activate the pre-configured virtual environment
.\venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r backend/requirements.txt
```

### Step 2: Start THREXIS Backend Server
```powershell
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
The backend API is now accessible at:
- **API Base:** `http://127.0.0.1:8000/api/v1`
- **Interactive Swagger Docs:** `http://127.0.0.1:8000/docs`
- **WebSocket:** `ws://127.0.0.1:8000/ws`

### Step 3: Start THREXIS Frontend Dashboard
In a separate terminal:
```powershell
cd "c:\Users\Vikranth Reddy\threxis_original\frontend"
npm run dev
```
Open your browser at **`http://localhost:5173/`**.

---

## 5. Live Ubuntu VirtualBox VM Integration

To monitor real Ubuntu security activity from Oracle VirtualBox:

### Network Setup
Configure your Ubuntu VM in VirtualBox with a **Host-Only Network Adapter** (typically `192.168.56.101` on guest and `192.168.56.1` on Windows host).

### Deploy Collector on Ubuntu Guest
Copy the `collector/` folder to the Ubuntu VM and execute:
```bash
cd collector
sudo chmod +x install_collector.sh threxis_collector.py
sudo ./install_collector.sh
```
Check status:
```bash
sudo systemctl status threxis-collector
```
The agent starts tailing `/var/log/auth.log` and `/var/log/syslog` with persistent offset tracking.

---

## 6. Live Classroom Demonstration Procedure

Execute the following 9-stage sequence for faculty demonstration:

| Stage | Action | Expected Workstation Response |
|---|---|---|
| **1. Baseline** | Start THREXIS and open `http://localhost:5173` | Command Center shows baseline readiness (e.g. 52.4%), VM status STANDBY/ONLINE, no fabricated alerts. |
| **2. Generate Activity** | Click **"Simulate SSH Attack"** in the header (or run `bash demo/generate_ssh_attack.sh` inside VM) | 4 failed SSH authentication attempts are transmitted to the Ingestion API. |
| **3. Live Detection** | Observe dashboard in real-time | Detection engine exceeds threshold ($3$ failures in $60$s); Alert `RULE-SSH-BRUTEFORCE` triggers. |
| **4. Threat Intelligence** | Click "Rationale" on alert | Mapped to MITRE ATT&CK `T1110` (Brute Force) & `T1110.001` (Password Guessing) with transparent evidence rationale. |
| **5. Forensic Readiness** | Open "Forensic Readiness" | Weighted readiness score adapts; evidence gaps and remediation ROI recommendations are displayed. |
| **6. Prioritization** | Open "Evidence Prioritization" | Adaptive strategy prioritizes SSH auth logs and user sessions within collection budget. |
| **7. Investigation** | Open "Incident Investigation" | Investigation case `CASE-...` displays synchronized chronological timeline. |
| **8. Evidence Vault** | Open "Evidence Vault" & click "Verify Integrity" | File preserved with SHA-256 hash. Verification recalculates hash and confirms bit-level match. |
| **9. Generate Report** | Click "Export Court-Admissible PDF" | Download and inspect the structured forensic PDF investigation report. |

---

## 7. Running Automated Test Suite

Run unit, engine, and end-to-end integration tests:
```powershell
.\venv\Scripts\python -m pytest backend/tests -v
```
All 11 tests pass with 100% success rate, validating:
- Ingestion deduplication and collector key authentication
- Weighted readiness scoring formula
- MITRE ATT&CK technique mapping and detection thresholds
- 5-strategy adaptive prioritization knapsack constraints
- SHA-256 cryptographic preservation and tamper detection
- PDF and JSON forensic report compilation
