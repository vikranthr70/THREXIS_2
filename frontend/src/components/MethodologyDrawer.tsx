import React, { useEffect } from 'react';
import { X } from 'lucide-react';
import type { ReadinessAssessment } from '../types';
import { describeWeighting } from '../utils/threatContext';
import { sentenceCase } from '../utils/format';

interface MethodologyDrawerProps {
  readiness: ReadinessAssessment;
  onClose: () => void;
}

const STATUS_FACTORS: [string, string][] = [
  ['Validated', '1.00'],
  ['Collected', '0.85'],
  ['Available', '0.60'],
  ['Missing / unavailable', '0.00'],
  ['Not applicable', 'excluded']
];

/** Slide-out explanation of how the readiness score is computed. */
export const MethodologyDrawer: React.FC<MethodologyDrawerProps> = ({ readiness, onClose }) => {
  const weighting = describeWeighting(readiness);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Readiness methodology">
        <div className="drawer-header">
          <span className="drawer-title">Readiness methodology</span>
          <button className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close"><X size={15} /></button>
        </div>
        <div className="drawer-body">
          <section>
            <div className="section-label">Formula</div>
            <div className="formula">Readiness (%) = 100 × Σ(wᵢ × sᵢ) / Σ(wᵢ)</div>
            <p className="text-sm text-secondary prose" style={{ marginTop: 8 }}>
              A weighted average over applicable evidence sources. <b className="text-body">wᵢ</b> is how important
              a source is for investigations; <b className="text-body">sᵢ</b> is how usable it currently is.
            </p>
          </section>

          <section>
            <div className="section-label">Current values</div>
            <dl className="kv">
              <dt>Σ(wᵢ × sᵢ)</dt><dd className="num">{readiness.weighted_sum.toFixed(3)}</dd>
              <dt>Σ(wᵢ)</dt><dd className="num">{readiness.total_weight.toFixed(3)}</dd>
              <dt>Score</dt><dd className="num">{readiness.score.toFixed(1)}%</dd>
              <dt>Category</dt><dd>{sentenceCase(readiness.category)}</dd>
              <dt>Applicable sources</dt><dd className="num">{readiness.sources.length}</dd>
            </dl>
          </section>

          <section>
            <div className="section-label">Status factor (sᵢ)</div>
            <dl className="kv">
              {STATUS_FACTORS.map(([label, value]) => (
                <React.Fragment key={label}><dt>{label}</dt><dd className="num">{value}</dd></React.Fragment>
              ))}
            </dl>
          </section>

          <section>
            <div className="section-label">Threat-context weighting</div>
            {weighting.kind === 'adjusted' ? (
              <p className="text-sm prose">
                Active technique <b className="text-heading">{weighting.profile.technique}</b>: sources with ATT&CK
                affinity ≥ {weighting.profile.affinity_threshold} have their weight multiplied by
                ×{weighting.profile.multiplier} (capped at 1.0):{' '}
                <span className="text-heading">{weighting.profile.boosted_sources.join(', ')}</span>.
              </p>
            ) : (
              <p className="text-sm text-secondary prose">
                No active technique with a weight profile, so baseline weights apply. When a modeled technique is
                detected, the sources most relevant to it are weighted ×1.15.
              </p>
            )}
          </section>

          <section>
            <div className="section-label">Gap impact</div>
            <p className="text-sm text-secondary prose">
              Each recommendation's impact is the score gained if that source reached sᵢ = 1.0:
              100 × wᵢ(1 − sᵢ) / Σ(wᵢ). Impacts plus the current score sum to 100%.
            </p>
          </section>
        </div>
      </aside>
    </>
  );
};
