import React from 'react';
import { CheckCircle2, AlertTriangle, X } from 'lucide-react';
import type { AcquireSelectionResult } from '../types';

interface AcquisitionSummaryProps {
  result: AcquireSelectionResult;
  onDismiss?: () => void;
}

/**
 * Shows the outcome of preserving a prioritized selection: what went into the
 * Vault, and which selected sources need host-side collection (and why).
 */
export const AcquisitionSummary: React.FC<AcquisitionSummaryProps> = ({ result, onDismiss }) => {
  const { selection, acquired, skipped } = result;
  return (
    <div className="panel-inset stack" style={{ marginTop: 'var(--space-3)' }}>
      <div className="row-between">
        <span className="text-md text-secondary">
          Preserved for <span className="mono text-primary">{result.case_id}</span> from{' '}
          {selection.origin === 'server_adaptive'
            ? <>adaptive prioritization (budget {selection.budget}, context <span className="mono">{selection.threat_context}</span>)</>
            : <>the {selection.source_keys.length} sources selected on the Prioritization page</>}
        </span>
        {onDismiss && (
          <button className="btn btn-secondary btn-sm" onClick={onDismiss} aria-label="Dismiss">
            <X size={12} />
          </button>
        )}
      </div>

      {acquired.length > 0 ? (
        <div className="stack-sm">
          {acquired.map((a) => (
            <div key={a.evidence_id} className="row-sm wrap text-md">
              <CheckCircle2 size={13} className="text-teal" />
              <span className="strong">{a.source_name}</span>
              <span className="text-secondary">→ {a.evidence_id} · {a.record_count} records · SHA-256</span>
              <span className="mono text-muted text-xs">{a.sha256_hash.slice(0, 16)}…</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-md text-amber">Nothing could be preserved from THREXIS telemetry for this selection.</div>
      )}

      {skipped.length > 0 && (
        <div className="stack-sm">
          <div className="section-label" style={{ marginBottom: 0 }}>Not preserved ({skipped.length})</div>
          {skipped.map((s) => (
            <div key={s.source_key} className="row-sm text-md" style={{ alignItems: 'flex-start' }}>
              <AlertTriangle size={13} className="text-amber" style={{ flexShrink: 0, marginTop: '2px' }} />
              <span>
                <span className="strong">{s.source_name}</span>{' '}
                <span className="text-secondary">— {s.reason}</span>
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
