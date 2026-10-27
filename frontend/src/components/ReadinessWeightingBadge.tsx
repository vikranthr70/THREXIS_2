import React from 'react';
import type { ReadinessAssessment } from '../types';
import { describeWeighting } from '../utils/threatContext';
import { StatusDot } from './ui';

/**
 * Makes the threat-context weighting of the readiness score visible, so a
 * score change caused by re-weighting is never silent.
 */
export const ReadinessWeightingBadge: React.FC<{ readiness: ReadinessAssessment }> = ({ readiness }) => {
  const weighting = describeWeighting(readiness);

  if (weighting.kind === 'adjusted') {
    return (
      <StatusDot
        tone="warn"
        title={`Weights ×${weighting.profile.multiplier} for sources critical to ${weighting.profile.technique}: ${weighting.profile.boosted_sources.join(', ')}.`}
      >
        Threat-adjusted · {weighting.techniqueId}
      </StatusDot>
    );
  }
  if (weighting.kind === 'context-only') {
    return (
      <StatusDot tone="muted" title={`${weighting.techniqueId} has no threat-model profile; baseline weights apply.`}>
        Baseline weights · {weighting.techniqueId}
      </StatusDot>
    );
  }
  return <StatusDot tone="muted" title="No active threat technique; baseline weights apply.">Baseline weights</StatusDot>;
};
