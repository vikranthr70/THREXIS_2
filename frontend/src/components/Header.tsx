import React from 'react';
import { RefreshCw } from 'lucide-react';
import type { CollectorStatus, InvestigationCase } from '../types';
import { StatusDot } from './ui';
import { severityTone } from '../utils/format';
import { parseServerTime } from '../utils/time';

interface HeaderProps {
  currentTab: string;
  onRefresh: () => void;
  isRefreshing: boolean;
  /** Whether the last dashboard sync reached the backend. */
  apiReachable: boolean | null;
  collectorStatus: CollectorStatus | null;
  activeCase: InvestigationCase | null;
  totalEventsCount: number;
  lastEventTime: string | null;
  onOpenCase: () => void;
}

const TAB_TITLES: Record<string, string> = {
  'command-center': 'Command Center',
  readiness: 'Forensic Readiness',
  detection: 'Threats & ATT&CK',
  prioritization: 'Evidence Prioritization',
  investigation: 'Investigations',
  vault: 'Evidence Vault'
};

/**
 * Single place for environment and telemetry status (backend, collector, active case,
 * event stream). Previously this was spread across the header, sidebar and cards,
 * and the listener address was a hardcoded placeholder.
 */
export const Header: React.FC<HeaderProps> = ({
  currentTab,
  onRefresh,
  isRefreshing,
  apiReachable,
  collectorStatus,
  activeCase,
  totalEventsCount,
  lastEventTime,
  onOpenCase
}) => {
  const collector = collectorStatus?.collectors[0];
  const collectorOnline = !!collectorStatus && collectorStatus.connected_collectors_count > 0;

  return (
    <header className="topbar">
      <h1 className="topbar-title">{TAB_TITLES[currentTab] ?? 'THREXIS'}</h1>

      <div className="statusbar">
        <div className="statusbar-item">
          {apiReachable === null ? (
            <StatusDot tone="muted">Connecting…</StatusDot>
          ) : apiReachable ? (
            <StatusDot tone="ok">Backend</StatusDot>
          ) : (
            <StatusDot tone="crit">Backend unreachable</StatusDot>
          )}
        </div>

        <div className="statusbar-item">
          {collector ? (
            <StatusDot tone={collectorOnline ? 'ok' : 'warn'} title={collector.os_info}>
              Collector {collector.hostname} <span className="mono text-muted">{collector.ip_address}</span>
              {!collectorOnline && ' · offline'}
            </StatusDot>
          ) : (
            <StatusDot tone="muted">No collector</StatusDot>
          )}
        </div>

        {activeCase && (
          <div className="statusbar-item">
            <button className="statusbar-link" onClick={onOpenCase} title={activeCase.title}>
              <StatusDot tone={severityTone(activeCase.severity)}>{activeCase.case_id}</StatusDot>
            </button>
          </div>
        )}

        <div className="statusbar-item">
          <span className="num">{totalEventsCount}</span> events
          {lastEventTime && (
            <span className="text-muted">· last <span className="mono">{parseServerTime(lastEventTime).toLocaleTimeString()}</span></span>
          )}
        </div>

        <div className="statusbar-item" style={{ paddingRight: 0 }}>
          <button
            className="btn btn-ghost btn-icon btn-sm"
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Sync now"
            aria-label="Sync now"
          >
            <RefreshCw size={13} />
          </button>
        </div>
      </div>
    </header>
  );
};
