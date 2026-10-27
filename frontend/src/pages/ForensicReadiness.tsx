import React, { useState } from 'react';
import { Gauge, AlertOctagon, TrendingUp } from 'lucide-react';
import type { ReadinessAssessment } from '../types';
import { api } from '../services/api';
import { ReadinessWeightingBadge } from '../components/ReadinessWeightingBadge';

interface ForensicReadinessProps {
  readiness: ReadinessAssessment | null;
  onRefresh: () => void;
}

const getStatusBadgeClass = (status: string) => {
  switch (status) {
    case 'validated': return 'badge-teal';
    case 'collected': return 'badge-blue';
    case 'available': return 'badge-amber';
    case 'unavailable':
    case 'missing': return 'badge-red';
    default: return 'badge-neutral';
  }
};

export const ForensicReadiness: React.FC<ForensicReadinessProps> = ({
  readiness,
  onRefresh
}) => {
  const [updatingSource, setUpdatingSource] = useState<string | null>(null);
  const [statusChangeMessage, setStatusChangeMessage] = useState<string | null>(null);

  const handleStatusChange = async (sourceKey: string, newStatus: string) => {
    setUpdatingSource(sourceKey);
    try {
      await api.updateSourceStatus(sourceKey, newStatus);
      setStatusChangeMessage(`Updated ${sourceKey} status to '${newStatus}'. Recalculating weighted readiness.`);
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
        <Gauge size={40} className="empty-state-icon text-muted" style={{ marginBottom: 'var(--space-3)' }} />
        <div className="page-empty-title">Readiness Assessment Not Assessed</div>
        <div className="page-empty-hint">
          Connect Ubuntu telemetry agent or load baseline configuration to compute weighted forensic readiness.
        </div>
      </div>
    );
  }

  return (
    <div className="page-container page-stack">

      {/* Top Banner: Scientific Model & Core Score */}
      <div className="card card-accent">
        <div className="hero-row">
          <div>
            <div className="eyebrow">Operational Readiness Model</div>
            <div className="hero-title" style={{ fontSize: '20px', marginTop: '2px' }}>
              Threat-Informed Forensic Readiness: {readiness.score.toFixed(1)}%
            </div>
            <div className="hero-desc">
              Measures the degree to which digital evidence is readily preserved, accessible, and cryptographically verifiable
              to reconstruct incidents without compromising ongoing enterprise operations.
            </div>
            <div style={{ marginTop: 'var(--space-2)' }}>
              <ReadinessWeightingBadge readiness={readiness} />
            </div>
          </div>

          <div className="row-lg">
            <div className="stat-chip">
              <div className="label">Category</div>
              <div className="stat-chip-value text-teal">{readiness.category}</div>
            </div>
            <div className="stat-chip">
              <div className="label">Source Coverage</div>
              <div className="stat-chip-value">{readiness.coverage_percentage}%</div>
            </div>
          </div>
        </div>

        {/* Mathematical Model Callout */}
        <div className="panel-inset meta-strip">
          <div>
            <span className="text-muted">Mathematical Formula: </span>
            <span className="mono text-teal" style={{ fontWeight: 600 }}>{readiness.formula}</span>
          </div>
          <div className="row wrap" style={{ gap: 'var(--space-4)' }}>
            <span>Numerator: Σ(wᵢ × sᵢ) = <b>{readiness.weighted_sum.toFixed(3)}</b></span>
            <span>Denominator: Σ(wᵢ) = <b>{readiness.total_weight.toFixed(3)}</b></span>
            <span>Threat Context: <b>{readiness.threat_context}</b></span>
          </div>
        </div>

        {statusChangeMessage && <div className="notice">{statusChangeMessage}</div>}
      </div>

      {/* Evidence Source Status Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Gauge size={16} className="text-teal" />
            Monitored Evidence Sources & Readiness Factors (wᵢ × sᵢ)
          </span>
          <span className="text-sm text-muted">
            Model factors: Available (0.60) | Collected (0.85) | Validated (1.00) | Missing (0.00)
          </span>
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Evidence Source</th>
                <th>Category</th>
                <th>Threat Weight (wᵢ)</th>
                <th>Status</th>
                <th>Factor (sᵢ)</th>
                <th>Weighted Contribution</th>
                <th>Acquisition Cost</th>
                <th>Technical State / Source Path</th>
                <th>Simulate Lifecycle</th>
              </tr>
            </thead>
            <tbody>
              {readiness.sources.map((s) => (
                <tr key={s.source_key}>
                  <td className="cell-strong">{s.source_name}</td>
                  <td><span className="badge badge-neutral">{s.category}</span></td>
                  <td className={`mono ${s.weight >= 0.85 ? 'text-teal' : 'text-primary'}`}>{s.weight.toFixed(2)}</td>
                  <td>
                    <span className={`badge ${getStatusBadgeClass(s.status)}`}>{s.status.toUpperCase()}</span>
                  </td>
                  <td className="mono">{s.factor.toFixed(2)}</td>
                  <td className="mono cell-strong">{(s.weight * s.factor).toFixed(3)}</td>
                  <td className="mono text-muted">{s.collection_cost.toFixed(1)} units</td>
                  <td className="cell-note" style={{ maxWidth: '240px' }}>{s.details}</td>
                  <td>
                    <select
                      className="form-control form-control-sm"
                      value={s.status}
                      disabled={updatingSource === s.source_key}
                      onChange={(e) => handleStatusChange(s.source_key, e.target.value)}
                    >
                      <option value="missing">Missing (0.00)</option>
                      <option value="unavailable">Unavailable (0.00)</option>
                      <option value="available">Available (0.60)</option>
                      <option value="collected">Collected (0.85)</option>
                      <option value="validated">Validated (1.00)</option>
                      <option value="not_applicable">Not Applicable</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Readiness Gaps & Remediation Recommendations */}
      <div className="grid-2">
        {/* Gap Analysis */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <AlertOctagon size={16} className="text-amber" />
              Forensic Readiness Gap Analysis ({readiness.gaps.length} Gaps)
            </span>
            <span className="badge badge-amber">Deficiencies &lt; 0.85</span>
          </div>

          {readiness.gaps.length > 0 ? (
            <div className="stack">
              {readiness.gaps.map((gap) => (
                <div
                  key={gap.source_key}
                  className={`panel ${gap.weight >= 0.85 ? 'panel-accent-red' : 'panel-accent-amber'}`}
                >
                  <div className="row-between" style={{ marginBottom: 'var(--space-1)' }}>
                    <span className="strong" style={{ fontSize: '12.5px' }}>{gap.source_name}</span>
                    <span className="mono badge badge-red badge-sm">Penalty: -{gap.penalty.toFixed(2)} pts</span>
                  </div>
                  <div className="text-sm text-secondary">
                    Current Status: <b className="uppercase">{gap.status}</b> (factor {gap.current_factor})
                  </div>
                  <div className="text-sm text-teal" style={{ marginTop: 'var(--space-1)' }}>
                    Remediation: {gap.remediation}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">No readiness gaps — every applicable source is collected or validated.</div>
          )}
        </div>

        {/* Priority Remediation Recommendations */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <TrendingUp size={16} className="text-teal" />
              Priority Remediation Actions
            </span>
            <span className="badge badge-teal">ROI Impact Ranking</span>
          </div>

          {readiness.recommendations.length > 0 ? (
            <div className="stack">
              {readiness.recommendations.map((rec) => (
                <div key={rec.source} className="panel row-between">
                  <div>
                    <div className="row" style={{ marginBottom: '3px' }}>
                      <span className={`badge badge-xs ${rec.priority === 'HIGH' ? 'badge-red' : 'badge-amber'}`}>
                        {rec.priority}
                      </span>
                      <span className="strong text-base">{rec.source}</span>
                    </div>
                    <div className="text-sm text-secondary">{rec.action}</div>
                  </div>
                  <div className="badge badge-teal nowrap">{rec.impact}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">No remediation actions pending.</div>
          )}
        </div>
      </div>

    </div>
  );
};
