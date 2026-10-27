import type {
  DetectionAlert,
  InvestigationCase,
  MitreTechnique,
  ReadinessAssessment
} from '../types';

/**
 * ATT&CK techniques for which the backend readiness engine applies a
 * threat-specific weight profile (see calculate_readiness() in
 * backend/app/engines/readiness_engine.py). Any other technique passed as
 * threat_context is echoed back but scored with baseline weights.
 * Keep this in sync if new weight profiles are added server-side.
 */
export const WEIGHT_PROFILED_TECHNIQUES: ReadonlySet<string> = new Set(['T1110']);

const BASELINE_LABEL = 'Normal Baseline';
const CLOSED_STATUSES = new Set(['CLOSED', 'RESOLVED', 'DISMISSED']);
const SEVERITY_RANK: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export const isOpenStatus = (status?: string | null): boolean =>
  !!status && !CLOSED_STATUSES.has(status.toUpperCase());

export const severityRank = (severity?: string | null): number =>
  SEVERITY_RANK[(severity || '').toUpperCase()] ?? 0;

/**
 * Orders alerts so the dominant activity comes first: most supporting events,
 * then highest severity, then most recently observed. Event count leads so a
 * sustained brute-force burst (T1110, many events) outranks a one-off
 * root-login alert (T1078.003, one event) raised by the same attack — otherwise
 * the active context would flip between techniques on every refresh.
 */
export const rankAlerts = (alerts: DetectionAlert[]): DetectionAlert[] =>
  [...alerts].sort(
    (a, b) =>
      (b.event_count || 0) - (a.event_count || 0) ||
      severityRank(b.severity) - severityRank(a.severity) ||
      new Date(b.last_event_at).getTime() - new Date(a.last_event_at).getTime()
  );

export interface ActiveThreat {
  techniqueId: string;
  /** Where the technique came from: a live alert, or (no open alerts) the open case. */
  origin: 'alert' | 'case';
  /** Open alerts mapped to this technique, ranked. Empty when origin === 'case'. */
  alerts: DetectionAlert[];
  /** Other distinct techniques with open alerts, ranked. */
  otherTechniqueIds: string[];
}

export function deriveActiveThreat(
  alerts: DetectionAlert[],
  activeCase: InvestigationCase | null
): ActiveThreat | null {
  const ranked = rankAlerts(alerts.filter((a) => isOpenStatus(a.status) && a.technique_id));

  if (ranked.length > 0) {
    const techniqueId = ranked[0].technique_id;
    const otherTechniqueIds = Array.from(
      new Set(ranked.map((a) => a.technique_id).filter((id) => id !== techniqueId))
    );
    return {
      techniqueId,
      origin: 'alert',
      alerts: ranked.filter((a) => a.technique_id === techniqueId),
      otherTechniqueIds
    };
  }

  if (activeCase && isOpenStatus(activeCase.status) && activeCase.primary_technique) {
    return { techniqueId: activeCase.primary_technique, origin: 'case', alerts: [], otherTechniqueIds: [] };
  }

  return null;
}

/** Exact technique match, falling back to the parent technique (T1078.003 → T1078). */
export function findTechnique(
  techniques: MitreTechnique[],
  techniqueId: string
): MitreTechnique | undefined {
  return (
    techniques.find((t) => t.id === techniqueId) ??
    techniques.find((t) => t.id === techniqueId.split('.')[0])
  );
}

export type ReadinessWeighting =
  | { kind: 'adjusted'; techniqueId: string }
  | { kind: 'context-only'; techniqueId: string }
  | { kind: 'baseline' };

/** Describes how the readiness score returned by the API was weighted. */
export function describeWeighting(readiness: ReadinessAssessment): ReadinessWeighting {
  const ctx = readiness.threat_context;
  if (!ctx || ctx === BASELINE_LABEL) return { kind: 'baseline' };
  if (WEIGHT_PROFILED_TECHNIQUES.has(ctx)) return { kind: 'adjusted', techniqueId: ctx };
  return { kind: 'context-only', techniqueId: ctx };
}

/**
 * Next investigative step, taken from the case record itself:
 * the analyst's "Recommended Action:" line in their notes if present,
 * otherwise the first unresolved question on the case.
 */
export function deriveNextAction(
  c: InvestigationCase
): { label: string; text: string; remainingQuestions: number } | null {
  const questions = (c.unresolved_questions || []).filter(Boolean);
  const match = (c.analyst_notes || '').match(/Recommended Action:\s*([^\n]+)/i);
  if (match && match[1].trim()) {
    return { label: 'Recommended Action · from analyst notes', text: match[1].trim(), remainingQuestions: questions.length };
  }
  if (questions.length > 0) {
    return { label: 'Open Investigative Question', text: questions[0], remainingQuestions: questions.length - 1 };
  }
  return null;
}
