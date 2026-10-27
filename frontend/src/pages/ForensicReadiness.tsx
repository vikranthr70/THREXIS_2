import React, { useState } from 'react';
import { Gauge, BookOpen } from 'lucide-react';
import type { ReadinessAssessment } from '../types';
import { api } from '../services/api';
import { ReadinessWeightingBadge } from '../components/ReadinessWeightingBadge';
import { MethodologyDrawer } from '../components/MethodologyDrawer';
import { InfoTip, StatusDot } from '../components/ui';
import { labelize, readinessTone, sentenceCase, sourceStatusTone } from '../utils/format';

interface ForensicReadinessProps {
  readiness: ReadinessAssessment | null;
  onRefresh: () => void;
}

const STATUS_OPTIONS: [string, string][] = [
  ['missing', 'Missing'],
  ['unavailable', 'Unavailable'],
  ['available', 'Available'],
  ['collected', 'Collected'],
  ['validated', 'Validated'],
  ['not_applicable', 'Not applicable']
];

export const ForensicReadiness: React.FC<ForensicReadinessProps> = ({ readiness, onRefresh }) => {
  const [updatingSource, setUpdatingSource] = useState<string | null>(null);
  const [statusChangeMessage, setStatusChangeMessage] = useState<string | null>(null);
  const [methodologyOpen, setMethodologyOpen] = useState(false);

  const handleStatusChange = async (sourceKey: string, newStatus: string) => {
    setUpdatingSource(sourceKey);
    try {
      await api.updateSourceStatus(sourceKey, newStatus);
      setStatusChangeMessage(`${sourceKey} set to ${labelize(newStatus)}. Score recalculated.`);
      onRefresh();
      setTimeout(() => setStatusChangeMessage(null), 4000);
    } catch (err: any) {
      console.error(err);
    } finally {
      setUpdatingSource(null);
    }
  };

  if (!readiness) {
    return (
      <div className="page-container page-empty">
        <Gauge size={32} />
        <div className="page-empty-title">Readiness not assessed</div>
        <div className="page-empty-hint">Waiting for the backend to report evidence source status.</div>
      </div>
    );
  }

  const tone = readinessTone(readiness.score);
  const missing = readiness.sources.filter((s) => s.factor === 0).length;

  return (
    <div className="page-container page-stack">

      {/* Summary */}
      <div className="card">
        <div className="card-body row-between wrap" style={{ alignItems: 'flex-end' }}>
          <div className="stack" style={{ gap: 2 }}>
            <div className="kpi-label">
              Forensic readiness
              <InfoTip label="How readiness is calculated">
                100 × Σ(wᵢ·sᵢ) / Σ(wᵢ) over applicable sources. See Methodology for factors and threat weighting.
              </InfoTip>
            </div>
            <div className={`kpi-value ${tone === 'crit' ? 'text-crit' : tone === 'warn' ? 'text-warn' : ''}`} style={{ fontSize: 28 }}>
              {readiness.score.toFixed(1)}%
            </div>
            <div className="kpi-sub">
              Score {readiness.weighted_sum.toFixed(2)} / {readiness.total_weight.toFixed(2)} · {sentenceCase(readiness.category)}
            </div>
          </div>

          <div className="row-lg wrap">
            <dl className="kv">
              <dt>Coverage</dt><dd className="num">{readiness.coverage_percentage}%</dd>
              <dt>Gaps</dt><dd><span className="num">{readiness.gaps_count}</span> below collected{missing > 0 && <span className="text-warn"> · {missing} missing</span>}</dd>
              <dt>Weighting</dt><dd><ReadinessWeightingBadge readiness={readiness} /></dd>
            </dl>
            <button className="btn btn-secondary" onClick={() => setMethodologyOpen(true)}>
              <BookOpen size={13} /> Methodology
            </button>
          </div>
        </div>
        {statusChangeMessage && <div className="card-footer text-sm text-secondary">{statusChangeMessage}</div>}
      </div>

      {/* Evidence sources */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Evidence sources</span>
          <span className="card-meta">{readiness.sources.length} monitored</span>
        </div>
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Category</th>
                <th>Status</th>
                <th>Details</th>
                <th className="num">Weight</th>
                <th className="num">Factor</th>
                <th className="num">Contribution</th>
                <th className="num">Cost</th>
                <th className="actions">Set status</th>
              </tr>
            </thead>
            <tbody>
              {readiness.sources.map((s) => (
                <tr key={s.source_key}>
                  <td className="cell-primary">{s.source_name}</td>
                  <td className="cell-secondary">{s.category}</td>
                  <td><StatusDot tone={sourceStatusTone(s.status, s.weight)}>{labelize(s.status)}</StatusDot></td>
                  <td className="cell-wrap" title={s.details}>{s.details}</td>
                  <td className="num">{s.weight.toFixed(2)}</td>
                  <td className="num">{s.factor.toFixed(2)}</td>
                  <td className="num text-heading">{(s.weight * s.factor).toFixed(3)}</td>
                  <td className="num cell-secondary">{s.collection_cost.toFixed(0)}</td>
                  <td className="actions">
                    <select
                      className="form-control form-control-sm"
                      aria-label={`Set status for ${s.source_name}`}
                      value={s.status}
                      disabled={updatingSource === s.source_key}
                      onChange={(e) => handleStatusChange(s.source_key, e.target.value)}
                    >
                      {STATUS_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Gaps & remediation */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Readiness gaps</span>
            <span className="card-meta">Sources below collected (sᵢ &lt; 0.85)</span>
          </div>
          {readiness.gaps.length > 0 ? (
            <div className="list">
              {readiness.gaps.map((gap) => (
                <div key={gap.source_key} className="list-row stack" style={{ gap: 3 }}>
                  <div className="row-between">
                    <StatusDot tone={sourceStatusTone(gap.status, gap.weight)}>
                      <span className="medium text-heading">{gap.source_name}</span>
                    </StatusDot>
                    <span className="text-sm text-secondary num">−{gap.penalty.toFixed(2)} weighted pts</span>
                  </div>
                  <div className="text-sm text-secondary">{labelize(gap.status)} · {gap.remediation}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">No gaps. Every applicable source is collected or validated.</div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Remediation priorities</span>
            <span className="card-meta">Impact = score gain if fully validated</span>
          </div>
          {readiness.recommendations.length > 0 ? (
            <div className="list">
              {readiness.recommendations.map((rec) => (
                <div key={rec.source} className="list-row row-between" style={{ alignItems: 'flex-start' }}>
                  <div className="stack grow" style={{ gap: 3 }}>
                    <StatusDot tone={rec.priority === 'HIGH' ? 'warn' : 'neutral'}>
                      <span className="medium text-heading">{rec.source}</span>
                      <span className="text-xs text-muted">{labelize(rec.priority)} priority</span>
                    </StatusDot>
                    <div className="text-sm text-secondary">{rec.action}</div>
                  </div>
                  <span className="text-sm text-heading num nowrap">{rec.impact.replace(' potential readiness increase', '')}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">No remediation actions pending.</div>
          )}
        </div>
      </div>

      {methodologyOpen && <MethodologyDrawer readiness={readiness} onClose={() => setMethodologyOpen(false)} />}
    </div>
  );
};
