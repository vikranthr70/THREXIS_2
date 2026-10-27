import type {
  DetectionAlert,
  InvestigationCase,
  MitreTechnique,
  ReadinessAssessment,
  WeightProfile
} from '../types';

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
  | { kind: 'adjusted'; techniqueId: string; profile: WeightProfile }
  | { kind: 'context-only'; techniqueId: string }
  | { kind: 'baseline' };

/**
 * Describes how the readiness score returned by the API was weighted, using the
 * backend's weight_profile (shared threat model in backend/app/core/threat_model.py).
 */
export function describeWeighting(readiness: ReadinessAssessment): ReadinessWeighting {
  const ctx = readiness.threat_context;
  if (readiness.weight_profile) {
    return { kind: 'adjusted', techniqueId: ctx, profile: readiness.weight_profile };
  }
  if (!ctx || ctx === BASELINE_LABEL) return { kind: 'baseline' };
  return { kind: 'context-only', techniqueId: ctx };
}

/** Threat contexts the prioritization engine has an affinity profile for. */
export const PRIORITIZATION_CONTEXTS: { id: string; label: string }[] = [
  { id: 'T1110', label: 'T1110: SSH Brute Force / Password Guessing' },
  { id: 'T1548.003', label: 'T1548.003: Privilege Escalation / Sudo Abuse' },
  { id: 'T1059.004', label: 'T1059.004: Unix Shell & Scripting Execution' },
  { id: 'BASELINE', label: 'BASELINE: Normal Security Operations' }
];

export interface PrioritizationContext {
  /** Context actually used for prioritization and Vault acquisition. */
  value: string;
  /** True when it follows the detected technique rather than a manual choice. */
  auto: boolean;
  /** Explanation shown next to the selector. */
  note: string;
}

/** Map a detected technique to a modeled prioritization context (exact, then parent). */
function modeledContextFor(techniqueId: string): string | null {
  const ids = PRIORITIZATION_CONTEXTS.map((c) => c.id);
  if (ids.includes(techniqueId)) return techniqueId;
  const parent = techniqueId.split('.')[0];
  return ids.includes(parent) ? parent : null;
}

export function resolvePrioritizationContext(
  activeThreat: ActiveThreat | null,
  manualOverride: string | null
): PrioritizationContext {
  if (manualOverride) {
    return { value: manualOverride, auto: false, note: 'Manually selected; not following live detections.' };
  }
  if (!activeThreat) {
    return { value: 'BASELINE', auto: true, note: 'No active detection, so normal operations are assumed.' };
  }
  const modeled = modeledContextFor(activeThreat.techniqueId);
  if (modeled) {
    return {
      value: modeled,
      auto: true,
      note: `Following the detected technique ${activeThreat.techniqueId}${activeThreat.origin === 'case' ? ' (from the open case)' : ''}.`
    };
  }
  return {
    value: 'BASELINE',
    auto: true,
    note: `Detected ${activeThreat.techniqueId} has no affinity profile yet, so BASELINE is used.`
  };
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
