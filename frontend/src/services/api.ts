import {
  ReadinessAssessment,
  SecurityEvent,
  DetectionAlert,
  MitreTechnique,
  PrioritizationResult,
  StrategyComparisonItem,
  InvestigationCase,
  EvidenceVaultItem,
  CollectorStatus,
  AcquireSelectionResult
} from '../types';

const API_BASE = '/api/v1';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`API error ${res.status}: ${errorText}`);
  }
  return res.json();
}

export const api = {
  // Telemetry & Collector
  getRecentEvents: (limit = 50, eventType?: string): Promise<SecurityEvent[]> => {
    const q = eventType ? `?limit=${limit}&event_type=${eventType}` : `?limit=${limit}`;
    return fetchJson(`${API_BASE}/telemetry/events${q}`);
  },

  getCollectorStatus: (): Promise<CollectorStatus> => {
    return fetchJson(`${API_BASE}/collector/status`);
  },

  // Forensic Readiness
  getReadiness: (threatContext?: string): Promise<ReadinessAssessment> => {
    const q = threatContext ? `?threat_context=${encodeURIComponent(threatContext)}` : '';
    return fetchJson(`${API_BASE}/readiness${q}`);
  },

  updateSourceStatus: (sourceKey: string, status: string, details?: string) => {
    return fetchJson(`${API_BASE}/readiness/source`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source_key: sourceKey, status, details })
    });
  },

  // Threat Detection & MITRE ATT&CK
  getAlerts: (): Promise<DetectionAlert[]> => {
    return fetchJson(`${API_BASE}/detection/alerts`);
  },

  getMitreTechniques: (): Promise<MitreTechnique[]> => {
    return fetchJson(`${API_BASE}/intelligence/techniques`);
  },

  // Adaptive Prioritization
  runPrioritization: (
    strategy: string,
    budget: number,
    threatContext?: string
  ): Promise<PrioritizationResult> => {
    return fetchJson(`${API_BASE}/prioritization/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ strategy, budget, threat_context: threatContext })
    });
  },

  compareStrategies: (
    budget: number,
    threatContext = 'T1110'
  ): Promise<{ budget: number; threat_context: string; strategies_comparison: StrategyComparisonItem[] }> => {
    return fetchJson(`${API_BASE}/prioritization/compare?budget=${budget}&threat_context=${threatContext}`);
  },

  // Incident Investigation
  getCases: (): Promise<InvestigationCase[]> => {
    return fetchJson(`${API_BASE}/investigation/cases`);
  },

  getCaseDetail: (caseId: string): Promise<any> => {
    return fetchJson(`${API_BASE}/investigation/case/${caseId}`);
  },

  updateCaseNotes: (caseId: string, notes: string, status?: string): Promise<InvestigationCase> => {
    return fetchJson(`${API_BASE}/investigation/case/${caseId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst_notes: notes, status })
    });
  },

  updateCaseStatus: (caseId: string, status: string): Promise<InvestigationCase> => {
    return fetchJson(`${API_BASE}/investigation/case/${caseId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
  },

  getReportDownloadUrl: (caseId: string, format: 'pdf' | 'json'): string => {
    return `${API_BASE}/investigation/case/${caseId}/report.${format}`;
  },

  // Evidence Vault
  getVaultItems: (caseId?: string): Promise<EvidenceVaultItem[]> => {
    const q = caseId ? `?case_id=${caseId}` : '';
    return fetchJson(`${API_BASE}/vault/items${q}`);
  },

  acquireEvidence: (
    caseId: string,
    sourceKey: string,
    sourceTitle: string,
    eventIds: string[],
    originalSourcePath = '/var/log/auth.log'
  ): Promise<EvidenceVaultItem> => {
    return fetchJson(`${API_BASE}/vault/acquire`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        case_id: caseId,
        source_key: sourceKey,
        source_title: sourceTitle,
        event_ids: eventIds,
        original_source_path: originalSourcePath
      })
    });
  },

  /**
   * Preserve a prioritized selection for a case. Pass sourceKeys to preserve exactly
   * what was selected on the Prioritization page; omit them to let the server run
   * adaptive prioritization with the given budget/threat context.
   */
  acquireSelection: (
    caseId: string,
    opts: { sourceKeys?: string[]; budget?: number; threatContext?: string } = {}
  ): Promise<AcquireSelectionResult> => {
    return fetchJson(`${API_BASE}/vault/acquire-selection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        case_id: caseId,
        source_keys: opts.sourceKeys,
        budget: opts.budget,
        threat_context: opts.threatContext
      })
    });
  },

  verifyIntegrity: (evidenceId: string): Promise<any> => {
    return fetchJson(`${API_BASE}/vault/verify/${evidenceId}`, {
      method: 'POST'
    });
  }
};
