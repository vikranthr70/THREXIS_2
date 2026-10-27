import React from 'react';
import { Info } from 'lucide-react';
import type { Tone } from '../utils/format';

/** "● Label" status indicator. Use for states; reserve Chip for things that must stand out. */
export const StatusDot: React.FC<{ tone?: Tone; children: React.ReactNode; title?: string }> = ({
  tone = 'neutral',
  children,
  title
}) => (
  <span className={`status status-${tone}`} title={title}>{children}</span>
);

/** Borderless tinted chip, e.g. severity or an ATT&CK technique ID. */
export const Chip: React.FC<{ tone?: Tone; children: React.ReactNode; title?: string }> = ({
  tone = 'neutral',
  children,
  title
}) => (
  <span className={`chip ${tone === 'neutral' || tone === 'muted' ? '' : `chip-${tone}`}`} title={title}>
    {children}
  </span>
);

/** (i) trigger that reveals an explanation on hover or keyboard focus. */
export const InfoTip: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <span className="infotip">
    <button type="button" className="infotip-trigger" aria-label={label}>
      <Info size={13} />
    </button>
    <span className="infotip-content" role="tooltip">{children}</span>
  </span>
);
