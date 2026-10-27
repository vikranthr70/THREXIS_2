/**
 * The backend stores UTC datetimes without a timezone and serializes some of them
 * without a "Z" (e.g. "2026-10-27T17:12:59"). JavaScript parses such strings as
 * *local* time, which shifted times by the viewer's UTC offset (5h30 in India),
 * broke "received in last 5m", and mislabeled the UTC column. Always parse via this.
 */
export function parseServerTime(ts: string | null | undefined): Date {
  if (!ts) return new Date(NaN);
  const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(ts);
  return new Date(hasZone ? ts : `${ts}Z`);
}
