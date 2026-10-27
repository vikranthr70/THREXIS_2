import React, { useState } from 'react';
import { ExternalLink, Search, FileSearch } from 'lucide-react';
import type { DetectionAlert, MitreTechnique } from '../types';
import { isOpenStatus } from '../utils/threatContext';
import { parseServerTime } from '../utils/time';
import { Chip, StatusDot } from '../components/ui';
import { labelize, severityTone } from '../utils/format';

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

  // Fall back to the first technique once the list has loaded.
  const selectedTechnique = techniques.find(t => t.id === selectedTechniqueId) ?? techniques[0] ?? null;

  const openAlerts = alerts.filter(a => isOpenStatus(a.status));
  const q = searchQuery.toLowerCase();
  const filteredTechniques = techniques.filter(t =>
    t.name.toLowerCase().includes(q) ||
    t.id.toLowerCase().includes(q) ||
    t.tactics.some(tac => tac.toLowerCase().includes(q))
  );

  return (
    <div className="page-container page-stack">

      {/* Detection alerts */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Detection alerts</span>
          <span className="card-meta">{openAlerts.length} open · {alerts.length - openAlerts.length} closed</span>
        </div>

        {alerts.length > 0 ? (
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Technique</th>
                  <th>Tactic</th>
                  <th>Target user</th>
                  <th>Source IP</th>
                  <th>Status</th>
                  <th className="num">Events</th>
                  <th className="num">Last seen</th>
                  <th className="actions"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alt) => {
                  const open = isOpenStatus(alt.status);
                  return (
                    <tr key={alt.alert_id} className={open ? '' : 'row-dimmed'}>
                      <td className="cell-primary">
                        {alt.rule_name}
                        <div className="text-xs text-muted">{alt.alert_id}</div>
                      </td>
                      <td><Chip tone={open ? severityTone(alt.severity) : 'neutral'}>{alt.severity}</Chip></td>
                      <td><Chip tone="tag">{alt.technique_id}</Chip></td>
                      <td className="cell-secondary">{alt.tactic}</td>
                      <td>{alt.target_user || '—'}</td>
                      <td className="mono">{alt.source_ip || '—'}</td>
                      <td><StatusDot tone={open ? 'warn' : 'muted'}>{labelize(alt.status)}</StatusDot></td>
                      <td className="num">{alt.event_count}</td>
                      <td className="num mono cell-secondary">{parseServerTime(alt.last_event_at).toLocaleTimeString()}</td>
                      <td className="actions">
                        <div className="row" style={{ justifyContent: 'flex-end', gap: 4 }}>
                          <button className="btn btn-ghost btn-sm" onClick={() => setSelectedAlert(alt)}>Rationale</button>
                          <button className="btn btn-secondary btn-sm" onClick={onNavigateToInvestigation}>
                            <FileSearch size={12} /> Investigate
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-title">No alerts</div>
            <div className="empty-state-hint">No detection threshold has been reached.</div>
          </div>
        )}
      </div>

      {/* ATT&CK explorer */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">ATT&CK technique explorer</span>
          <div className="search-field">
            <Search size={13} />
            <input
              type="text"
              className="form-control"
              placeholder="Filter by ID, name or tactic"
              aria-label="Filter techniques"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>

        <div className="master-detail">
          <div className="select-list">
            {filteredTechniques.map((tech) => {
              const isSelected = selectedTechnique?.id === tech.id;
              const detected = openAlerts.some(a => a.technique_id.startsWith(tech.id));
              return (
                <button
                  key={tech.id}
                  type="button"
                  className={`select-item ${isSelected ? 'is-selected' : ''}`}
                  onClick={() => setSelectedTechniqueId(tech.id)}
                >
                  <div className="row-between">
                    <span className="row">
                      <Chip tone="tag">{tech.id}</Chip>
                      <span className="text-heading medium">{tech.name}</span>
                    </span>
                    {detected && <StatusDot tone="crit">Detected</StatusDot>}
                  </div>
                  <div className="text-xs text-muted" style={{ marginTop: 3 }}>{tech.tactics.join(' · ')}</div>
                </button>
              );
            })}
            {filteredTechniques.length === 0 && (
              <div className="empty-state">No techniques match “{searchQuery}”.</div>
            )}
          </div>

          {selectedTechnique ? (
            <div className="detail-pane">
              <div className="row-between" style={{ alignItems: 'flex-start' }}>
                <div className="stack" style={{ gap: 4 }}>
                  <div className="row">
                    <Chip tone="tag">{selectedTechnique.id}</Chip>
                    <h2 className="strong" style={{ fontSize: 15 }}>{selectedTechnique.name}</h2>
                  </div>
                  <div className="text-sm text-secondary">{selectedTechnique.tactics.join(' · ')}</div>
                </div>
                <a href={selectedTechnique.url} target="_blank" rel="noopener noreferrer" className="btn btn-ghost btn-sm">
                  View on attack.mitre.org <ExternalLink size={12} />
                </a>
              </div>

              <section>
                <div className="section-label">Description</div>
                <p className="text-sm prose">{selectedTechnique.description}</p>
              </section>

              {selectedTechnique.subtechniques && selectedTechnique.subtechniques.length > 0 && (
                <section>
                  <div className="section-label">Sub-techniques</div>
                  <div className="stack">
                    {selectedTechnique.subtechniques.map((sub) => (
                      <div key={sub.id} className="row" style={{ alignItems: 'baseline' }}>
                        <Chip tone="tag">{sub.id}</Chip>
                        <span className="text-sm">
                          <span className="text-heading medium">{sub.name}</span>
                          <span className="text-secondary"> — {sub.description}</span>
                        </span>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              <section>
                <div className="section-label">Detection</div>
                <p className="text-sm text-secondary prose">{selectedTechnique.detection_methods}</p>
              </section>

              <section>
                <div className="section-label">Evidence sources</div>
                <ul className="text-sm" style={{ paddingLeft: 16, display: 'grid', gap: 2 }}>
                  {selectedTechnique.evidence_sources.map((src) => <li key={src}>{src}</li>)}
                </ul>
              </section>
            </div>
          ) : (
            <div className="empty-state">Select a technique.</div>
          )}
        </div>
      </div>

      {selectedAlert && (
        <div className="modal-backdrop" onClick={() => setSelectedAlert(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">Mapping rationale · {selectedAlert.alert_id}</span>
              <button className="btn btn-ghost btn-sm" onClick={() => setSelectedAlert(null)}>Close</button>
            </div>
            <div className="modal-body">
              <dl className="kv">
                <dt>Rule</dt><dd>{selectedAlert.rule_name} <span className="text-muted">({selectedAlert.rule_id})</span></dd>
                <dt>Technique</dt><dd className="row"><Chip tone="tag">{selectedAlert.technique_id}</Chip>{selectedAlert.technique_name}</dd>
                <dt>Tactic</dt><dd>{selectedAlert.tactic}</dd>
                <dt>Severity</dt><dd><Chip tone={severityTone(selectedAlert.severity)}>{selectedAlert.severity}</Chip></dd>
              </dl>
              <section>
                <div className="section-label">Detection</div>
                <p className="prose">{selectedAlert.explanation}</p>
              </section>
              <section>
                <div className="section-label">Why this technique</div>
                <p className="prose text-secondary">{selectedAlert.rationale}</p>
              </section>
              <section>
                <div className="section-label">Supporting events ({selectedAlert.supporting_event_ids.length})</div>
                <div className="text-xs text-secondary" style={{ wordBreak: 'break-all' }}>
                  {selectedAlert.supporting_event_ids.join(', ')}
                </div>
              </section>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
