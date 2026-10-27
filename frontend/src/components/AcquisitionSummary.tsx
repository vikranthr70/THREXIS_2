import React from 'react';
import { X } from 'lucide-react';
import type { AcquireSelectionResult } from '../types';
import { StatusDot } from './ui';

interface AcquisitionSummaryProps {
  result: AcquireSelectionResult;
  onDismiss?: () => void;
  action?: React.ReactNode;
}

/**
 * Outcome of preserving a prioritized selection: what went into the Vault, and which
 * selected sources need host-side collection (and why).
 */
export const AcquisitionSummary: React.FC<AcquisitionSummaryProps> = ({ result, onDismiss, action }) => {
  const { selection, acquired, skipped } = result;
  return (
    <div className="acq">
      <div className="row-between" style={{ padding: '10px 16px' }}>
        <span className="text-sm text-secondary">
          Preserved for <b className="text-body">{result.case_id}</b> from{' '}
          {selection.origin === 'server_adaptive'
            ? <>adaptive prioritization (budget {selection.budget}, {selection.threat_context})</>
            : <>{selection.source_keys.length} selected sources</>}
        </span>
        <div className="row">
          {action}
          {onDismiss && (
            <button className="btn btn-ghost btn-icon btn-sm" onClick={onDismiss} aria-label="Dismiss"><X size={13} /></button>
          )}
        </div>
      </div>
      <div className="list">
        {acquired.map((a) => (
          <div key={a.evidence_id} className="list-row row-between">
            <StatusDot tone="ok">{a.source_name}</StatusDot>
            <span className="text-sm text-secondary row">
              {a.evidence_id} · <span className="num">{a.record_count}</span> records ·
              <span className="mono text-muted">{a.sha256_hash.slice(0, 16)}…</span>
            </span>
          </div>
        ))}
        {skipped.map((s) => (
          <div key={s.source_key} className="list-row row-between">
            <StatusDot tone="warn">{s.source_name}</StatusDot>
            <span className="text-sm text-secondary" style={{ textAlign: 'right' }}>{s.reason}</span>
          </div>
        ))}
        {acquired.length === 0 && skipped.length === 0 && (
          <div className="list-row text-sm text-secondary">Nothing was selected.</div>
        )}
      </div>
    </div>
  );
};
