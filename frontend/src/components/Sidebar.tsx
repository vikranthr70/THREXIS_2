import React from 'react';
import { Gauge, Crosshair, ListOrdered, FileSearch, Vault, LayoutDashboard } from 'lucide-react';
import type { InvestigationCase } from '../types';

interface SidebarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  activeCase: InvestigationCase | null;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, setCurrentTab, activeCase }) => {
  // Indicators only where they reflect real state: the dot marks an open case.
  const navItems = [
    { id: 'command-center', label: 'Command Center', icon: LayoutDashboard, indicator: false },
    { id: 'readiness', label: 'Forensic Readiness', icon: Gauge, indicator: false },
    { id: 'detection', label: 'Threats & ATT&CK', icon: Crosshair, indicator: false },
    { id: 'prioritization', label: 'Evidence Prioritization', icon: ListOrdered, indicator: false },
    { id: 'investigation', label: 'Investigations', icon: FileSearch, indicator: !!activeCase },
    { id: 'vault', label: 'Evidence Vault', icon: Vault, indicator: false },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-name">THREXIS</div>
        <div className="sidebar-brand-sub">Forensic readiness</div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentTab(item.id)}
              className={`nav-item ${isActive ? 'is-active' : ''}`}
              aria-current={isActive ? 'page' : undefined}
            >
              <span className="row">
                <Icon size={15} />
                <span>{item.label}</span>
              </span>
              {item.indicator && <span className="nav-dot" title={`Open case ${activeCase?.case_id}`} />}
            </button>
          );
        })}
      </nav>
    </aside>
  );
};
