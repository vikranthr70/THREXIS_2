/**
 * Mapping from operational state to visual tone. Keeping this in one place is what
 * keeps colour meaningful: only these functions decide when something is red,
 * amber or emerald.
 */
export type Tone = 'crit' | 'warn' | 'ok' | 'tag' | 'neutral' | 'muted';

/** Alert / case severity. Only CRITICAL and HIGH are drawn in alert colours. */
export const severityTone = (severity?: string | null): Tone => {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL': return 'crit';
    case 'HIGH': return 'crit';
    case 'MEDIUM': return 'warn';
    default: return 'neutral';
  }
};

/** Evidence source status. Gaps are amber (red when the source is high-weight). */
export const sourceStatusTone = (status: string, weight = 0): Tone => {
  switch (status) {
    case 'validated': return 'ok';
    case 'collected': return 'ok';
    case 'available': return 'neutral';
    case 'missing':
    case 'unavailable':
    case 'unknown': return weight >= 0.9 ? 'crit' : 'warn';
    default: return 'muted';
  }
};

/** Readiness category -> tone (deficient thresholds are alert colours). */
export const readinessTone = (score: number): Tone =>
  score >= 80 ? 'ok' : score >= 60 ? 'neutral' : score >= 40 ? 'warn' : 'crit';

/** "UNDER_REVIEW" -> "Under review", "missing" -> "Missing". */
export const labelize = (value?: string | null): string => {
  if (!value) return '';
  const s = value.replace(/_/g, ' ').toLowerCase();
  return s.charAt(0).toUpperCase() + s.slice(1);
};

/** "CRITICAL EVIDENCE BLINDSPOT" -> "Critical evidence blindspot". */
export const sentenceCase = labelize;

export const fmtBytes = (n: number): string => {
  if (!Number.isFinite(n)) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
};
