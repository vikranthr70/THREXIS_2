import React from 'react';
import { Crosshair } from 'lucide-react';
import type { ReadinessAssessment } from '../types';
import { describeWeighting } from '../utils/threatContext';

/**
 * Makes the threat-context weighting of the readiness score visible, so a
 * score change caused by re-weighting is never silent.
 */
export const ReadinessWeightingBadge: React.FC<{ readiness: ReadinessAssessment }> = ({ readiness }) => {
  const weighting = describeWeighting(readiness);

  if (weighting.kind === 'adjusted') {
    return (
      <span
        className="badge badge-amber"
        title={`Weights ×${weighting.profile.multiplier} for sources critical to ${weighting.profile.technique} (ATT&CK affinity ≥ ${weighting.profile.affinity_threshold}): ${weighting.profile.boosted_sources.join(', ')}. Without an active threat the score uses baseline weights.`}
      >
        <Crosshair size={11} />
        THREAT-ADJUSTED · {weighting.techniqueId}
      </span>
    );
  }

  if (weighting.kind === 'context-only') {
    return (
      <span
        className="badge badge-neutral"
        title={`Active technique ${weighting.techniqueId} has no threat-model profile, so baseline weights apply.`}
      >
        BASELINE WEIGHTS · {weighting.techniqueId}
      </span>
    );
  }

  return (
    <span className="badge badge-neutral" title="No active threat technique; baseline source weights apply.">
      BASELINE WEIGHTS
    </span>
  );
};
