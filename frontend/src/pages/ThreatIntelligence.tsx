import React, { useState } from 'react';
import { Crosshair, ExternalLink, ShieldAlert, FileSearch, Search } from 'lucide-react';
import type { DetectionAlert, MitreTechnique } from '../types';
import { isOpenStatus } from '../utils/threatContext';
import { parseServerTime } from '../utils/time';

interface ThreatIntelligenceProps {
  alerts: DetectionAlert[];
  techniques: MitreTechnique[];
  onNavigateToInvestigation: () => void;
}

export const ThreatIntelligence: React.FC<ThreatIntelligenceProps> = ({
  alerts,
  techniques,
  onNavigateToInvestigation
}) => {
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<DetectionAlert | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Fall back to the first technique once the list has loaded (the list can
  // arrive after first render, which previously left the detail pane empty).
  const selectedTechnique =
    techniques.find(t => t.id === selectedTechniqueId) ?? techniques[0] ?? null;

  const openAlerts = alerts.filter(a => isOpenStatus(a.status));
  const q = searchQuery.toLowerCase();
  const filteredTechniques = techniques.filter(t =>
    t.name.toLowerCase().includes(q) ||
    t.id.toLowerCase().includes(q) ||
    t.tactics.some(tac => tac.toLowerCase().includes(q))
  );

  return (
    <div className="page-container page-stack">

      {/* Live Alerts Section */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <ShieldAlert size={16} className={openAlerts.length > 0 ? 'text-red' : 'text-teal'} />
            Threat Detection Alerts ({openAlerts.length} open · {alerts.length - openAlerts.length} closed)
          </span>
          <span className="badge badge-neutral">Deterministic Correlation</span>
        </div>

        {alerts.length > 0 ? (
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Alert ID</th>
                  <th>Detection Rule</th>
                  <th>Severity</th>
                  <th>MITRE Technique</th>
                  <th>Tactic</th>
                  <th>Target User</th>
                  <th>Source IP</th>
                  <th>Event Count</th>
                  <th>Status</th>
                  <th>Last Observed</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alt) => (
                  <tr key={alt.alert_id} className={isOpenStatus(alt.status) ? '' : 'row-dimmed'}>
                    <td className="mono cell-id">{alt.alert_id}</td>
                    <td className="text-primary">{alt.rule_name}</td>
                    <td>
                      <span className={`badge ${alt.severity === 'CRITICAL' || alt.severity === 'HIGH' ? 'badge-red' : 'badge-amber'}`}>
                        {alt.severity}
                      </span>
                    </td>
                    <td className="mono text-teal">{alt.technique_id}</td>
                    <td><span className="badge badge-neutral">{alt.tactic}</span></td>
                    <td className="mono">{alt.target_user || 'N/A'}</td>
                    <td className="mono">{alt.source_ip || 'N/A'}</td>
                    <td className="mono cell-strong">{alt.event_count} events</td>
                    <td className="mono cell-small">{alt.status}</td>
                    <td className="mono cell-small">{parseServerTime(alt.last_event_at).toLocaleTimeString()}</td>
                    <td>
                      <div className="row-sm">
                        <button className="btn btn-secondary btn-sm" onClick={() => setSelectedAlert(alt)}>
                          Rationale
                        </button>
                        <button className="btn btn-primary btn-sm" onClick={onNavigateToInvestigation}>
                          <FileSearch size={11} /> Investigate
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            No alerts triggered. Threshold has not been reached for SSH authentication failures or unauthorized sudo attempts.
          </div>
        )}
      </div>

      {/* MITRE ATT&CK Knowledge Base Explorer */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Crosshair size={16} className="text-teal" />
            MITRE ATT&CK Enterprise Threat Intelligence Matrix
          </span>
          <div className="search-field">
            <Search size={13} />
            <input
              type="text"
              className="form-control"
              placeholder="Search technique or tactic..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>

        <div className="master-detail">
          {/* Technique list */}
          <div className="select-list">
            {filteredTechniques.map((tech) => {
              const isSelected = selectedTechnique?.id === tech.id;
              const hasAlert = openAlerts.some(a => a.technique_id.startsWith(tech.id));
              return (
                <button
                  key={tech.id}
                  type="button"
                  className={`select-item ${isSelected ? 'is-selected' : ''}`}
                  onClick={() => setSelectedTechniqueId(tech.id)}
                >
                  <div className="row-between" style={{ marginBottom: '3px' }}>
                    <span className={`mono text-base ${isSelected ? 'text-teal' : 'text-primary'}`} style={{ fontWeight: 600 }}>
                      {tech.id}
                    </span>
                    {hasAlert && <span className="badge badge-red badge-xs">ACTIVE DETECT</span>}
                  </div>
                  <div className={`text-base ${isSelected ? 'text-primary' : 'text-secondary'}`} style={{ fontWeight: 500 }}>
                    {tech.name}
                  </div>
                  <div className="row wrap" style={{ gap: 'var(--space-1)', marginTop: 'var(--space-1)' }}>
                    {tech.tactics.map((t) => (
                      <span key={t} className="badge badge-neutral badge-xs">{t}</span>
                    ))}
                  </div>
                </button>
              );
            })}
            {filteredTechniques.length === 0 && (
              <div className="empty-state">No techniques match “{searchQuery}”.</div>
            )}
          </div>

          {/* Selected Technique Detail View */}
          {selectedTechnique ? (
            <div className="detail-pane">
              <div className="row-between" style={{ alignItems: 'flex-start' }}>
                <div>
                  <div className="row">
                    <span className="mono badge badge-teal" style={{ fontSize: '13px', padding: '2px 8px' }}>
                      {selectedTechnique.id}
                    </span>
                    <h2 className="strong" style={{ fontSize: '16px', fontWeight: 700 }}>{selectedTechnique.name}</h2>
                  </div>
                  <div className="row-sm wrap" style={{ marginTop: '6px' }}>
                    {selectedTechnique.tactics.map((tac) => (
                      <span key={tac} className="badge badge-neutral">{tac}</span>
                    ))}
                  </div>
                </div>

                <a
                  href={selectedTechnique.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-secondary btn-sm"
                >
                  Official ATT&CK Page <ExternalLink size={12} />
                </a>
              </div>

              <div>
                <div className="section-label">Technique Description</div>
                <p className="text-base text-secondary" style={{ lineHeight: 1.55 }}>{selectedTechnique.description}</p>
              </div>

              {selectedTechnique.subtechniques && selectedTechnique.subtechniques.length > 0 && (
                <div>
                  <div className="section-label">Grounded Subtechniques</div>
                  <div className="stack-sm">
                    {selectedTechnique.subtechniques.map((sub) => (
                      <div key={sub.id} className="sub-item">
                        <div className="row-sm">
                          <span className="mono text-teal text-md" style={{ fontWeight: 600 }}>{sub.id}</span>
                          <span className="text-primary text-base" style={{ fontWeight: 500 }}>{sub.name}</span>
                        </div>
                        <div className="text-sm text-muted" style={{ marginTop: '2px' }}>{sub.description}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <div className="section-label">Detection Methods</div>
                <div className="text-md text-secondary prose">{selectedTechnique.detection_methods}</div>
              </div>

              <div>
                <div className="section-label">Required Digital Forensic Evidence Sources</div>
                <div className="row-sm wrap">
                  {selectedTechnique.evidence_sources.map((src) => (
                    <span key={src} className="badge badge-teal">{src}</span>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="empty-state">
              Select a MITRE technique to inspect details and required forensic sources.
            </div>
          )}
        </div>
      </div>

      {/* Rationale Modal */}
      {selectedAlert && (
        <div className="modal-backdrop" onClick={() => setSelectedAlert(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">Mapping Rationale: {selectedAlert.alert_id}</span>
              <button className="btn btn-secondary" onClick={() => setSelectedAlert(null)}>Close</button>
            </div>

            <div className="modal-body">
              <div><b>Rule:</b> {selectedAlert.rule_name} ({selectedAlert.rule_id})</div>
              <div>
                <b>Assigned ATT&CK Technique:</b>{' '}
                <span className="mono badge badge-teal">{selectedAlert.technique_id} - {selectedAlert.technique_name}</span>
              </div>
              <div><b>Tactic:</b> {selectedAlert.tactic}</div>
              <div><b>Detection Explanation:</b> {selectedAlert.explanation}</div>

              <div className="panel-inset panel-accent" style={{ marginTop: 'var(--space-2)', padding: 'var(--space-3)' }}>
                <div className="eyebrow" style={{ marginBottom: 'var(--space-1)', letterSpacing: 0 }}>
                  Transparent Evidentiary Rationale:
                </div>
                <div className="text-primary" style={{ lineHeight: 1.55 }}>{selectedAlert.rationale}</div>
              </div>

              <div>
                <b>Supporting Event IDs:</b>
                <div className="row-sm wrap" style={{ marginTop: 'var(--space-1)' }}>
                  {selectedAlert.supporting_event_ids.map((id) => (
                    <span key={id} className="mono badge badge-neutral badge-sm">{id}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
