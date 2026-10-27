import React from 'react';
import { RefreshCw, Radio, Server } from 'lucide-react';

interface HeaderProps {
  currentTab: string;
  onRefresh: () => void;
  isRefreshing: boolean;
}

const TAB_TITLES: Record<string, { title: string; subtitle: string }> = {
  'command-center': {
    title: 'Command Center',
    subtitle: 'Unified operational monitoring, forensic readiness telemetry, and active incident response'
  },
  'readiness': {
    title: 'Forensic Readiness Engine',
    subtitle: 'Threat-informed weighted evidence readiness assessment and forensic gap remediation'
  },
  'detection': {
    title: 'Threat Detection & MITRE ATT&CK',
    subtitle: 'Heuristic rule correlation with deterministic ATT&CK Enterprise behavioral mapping'
  },
  'prioritization': {
    title: 'Adaptive Evidence Prioritization',
    subtitle: 'Resource-bounded evidence selection algorithms under dynamic threat context shifts'
  },
  'investigation': {
    title: 'Incident Investigation Workspace',
    subtitle: 'Correlated event chronology, computed findings, case lifecycle and forensic reporting'
  },
  'vault': {
    title: 'Forensic Evidence Vault',
    subtitle: 'Tamper-evident preservation with SHA-256 cryptographic chain-of-custody verification'
  }
};

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  onRefresh,
  isRefreshing
}) => {
  const info = TAB_TITLES[currentTab] || { title: 'THREXIS', subtitle: 'Workstation' };

  return (
    <header style={{
      height: '60px',
      backgroundColor: 'var(--bg-surface)',
      borderBottom: '1px solid var(--border-subtle)',
      padding: '0 24px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      flexShrink: 0
    }}>
      <div>
        <h1 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          {info.title}
        </h1>
        <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          {info.subtitle}
        </p>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        {/* Real Ingestion Endpoint Status Indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '4px 10px',
          backgroundColor: 'var(--bg-core)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '3px',
          fontSize: '11px'
        }}>
          <Server size={13} style={{ color: 'var(--teal-glow)' }} />
          <span style={{ color: 'var(--text-muted)' }}>Listener:</span>
          <span className="mono" style={{ color: 'var(--text-primary)', fontWeight: 500 }}>192.168.56.1:8000</span>
          <span className="badge badge-teal" style={{ padding: '1px 5px', fontSize: '9.5px' }}>
            <span className="pulse-indicator" style={{ width: '5px', height: '5px' }}></span>
            ACTIVE
          </span>
        </div>

        <button
          className="btn btn-secondary"
          onClick={onRefresh}
          disabled={isRefreshing}
          style={{ fontSize: '11.5px', padding: '5px 10px' }}
        >
          <RefreshCw size={13} className={isRefreshing ? 'animate-spin' : ''} />
          <span>Sync</span>
        </button>
      </div>
    </header>
  );
};
