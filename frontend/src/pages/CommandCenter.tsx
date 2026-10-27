import React, { useState } from 'react';
import {
  Gauge,
  Activity,
  AlertTriangle,
  ShieldCheck,
  Clock,
  ArrowRight,
  Layers,
  FileText
} from 'lucide-react';
import type {
  ReadinessAssessment,
  SecurityEvent,
  DetectionAlert,
  CollectorStatus,
  InvestigationCase,
  MitreTechnique
} from '../types';
import { ReadinessWeightingBadge } from '../components/ReadinessWeightingBadge';
import {
  type ActiveThreat,
  deriveNextAction,
  findTechnique,
  isOpenStatus,
  severityRank
} from '../utils/threatContext';
import { parseServerTime } from '../utils/time';

interface CommandCenterProps {
  readiness: ReadinessAssessment | null;
  events: SecurityEvent[];
  alerts: DetectionAlert[];
  techniques: MitreTechnique[];
  activeThreat: ActiveThreat | null;
  collectorStatus: CollectorStatus | null;
  activeCase: InvestigationCase | null;
  onNavigate: (tab: string) => void;
}

const severityBadge = (severity?: string) =>
  severity === 'HIGH' || severity === 'CRITICAL' ? 'badge-red' : severity === 'MEDIUM' ? 'badge-amber' : 'badge-neutral';

const segmentClass = (factor: number) =>
  factor >= 0.85 ? 'is-full' : factor >= 0.5 ? 'is-partial' : 'is-empty';

export const CommandCenter: React.FC<CommandCenterProps> = ({
  readiness,
  events,
  alerts,
  techniques,
  activeThreat,
  collectorStatus,
  activeCase,
  onNavigate
}) => {
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const collector = collectorStatus?.collectors[0];
  const isVmOnline = !!collectorStatus && collectorStatus.connected_collectors_count > 0;
  const openAlerts = alerts.filter(a => isOpenStatus(a.status));
  const highSeverityAlerts = openAlerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL');
  const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
  const eventsInLast5Min = events.filter(e => parseServerTime(e.timestamp) >= fiveMinAgo).length;

  const nextAction = activeCase ? deriveNextAction(activeCase) : null;
  // Same definition as the backend's coverage_percentage (available/collected/validated),
  // so the "x/n sources" fraction agrees with the percentage next to it.
  const coveredSources = readiness
    ? readiness.sources.filter(s => ['available', 'collected', 'validated'].includes(s.status)).length
    : 0;

  // ---- Threat context, derived from live alerts / the open case ----
  const technique = activeThreat ? findTechnique(techniques, activeThreat.techniqueId) : undefined;
  const leadAlert = activeThreat?.alerts[0];
  const threatEventCount = activeThreat?.alerts.reduce((n, a) => n + (a.event_count || 0), 0) ?? 0;
  const threatSeverity = activeThreat?.origin === 'alert'
    ? activeThreat.alerts.reduce((top, a) => (severityRank(a.severity) > severityRank(top) ? a.severity : top), activeThreat.alerts[0].severity as string)
    : activeCase?.severity;
  const techniqueName = technique?.name ?? leadAlert?.technique_name ?? 'Unmapped technique';
  const tactic = technique?.tactics[0] ?? leadAlert?.tactic;
  const lastObserved = leadAlert?.last_event_at ?? activeCase?.updated_at;

  return (
    <div className="page-container page-stack">

      {/* Top Row: Readiness Instrument & Operational Telemetry Metrics */}
      <div className="grid-2">
        {/* A. Forensic Readiness Instrument */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Gauge size={16} className="text-teal" />
              Forensic Readiness Instrument
            </span>
            {readiness && <span className="badge badge-teal">{readiness.category}</span>}
          </div>

          {readiness ? (
            <div>
              <div className="row wrap" style={{ alignItems: 'baseline', gap: '14px', marginBottom: 'var(--space-3)' }}>
                <span className="stat-value-xl">{readiness.score.toFixed(1)}%</span>
                <div className="text-md text-secondary">
                  <div>
                    Source Coverage: <b className="text-primary">{readiness.coverage_percentage}%</b>{' '}
                    ({coveredSources}/{readiness.sources.length} sources)
                  </div>
                  <div>
                    Evidence Gaps:{' '}
                    <b className={readiness.gaps_count > 0 ? 'text-amber' : 'text-teal'}>
                      {readiness.gaps_count} sources deficient
                    </b>
                  </div>
                </div>
              </div>

              {/* Segmented readiness meter: one segment per source, width ∝ weight */}
              <div style={{ marginBottom: '14px' }}>
                <div className="meter">
                  {readiness.sources.map((s) => (
                    <div
                      key={s.source_key}
                      className={`meter-segment ${segmentClass(s.factor)}`}
                      title={`${s.source_name}: factor ${s.factor} (weight: ${s.weight})`}
                      style={{ flex: s.weight }}
                    />
                  ))}
                </div>
                <div className="meter-scale">
                  <span>0% (Blindspot)</span>
                  <span className="mono">Σ(wᵢ × sᵢ) / Σ(wᵢ) = {readiness.weighted_sum.toFixed(2)} / {readiness.total_weight.toFixed(2)}</span>
                  <span>100% (Fully Validated)</span>
                </div>
              </div>

              <div className="panel row-between text-sm text-secondary">
                <ReadinessWeightingBadge readiness={readiness} />
                <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('readiness')}>
                  Inspect Scoring Engine <ArrowRight size={12} />
                </button>
              </div>
            </div>
          ) : (
            <div className="empty-state">Readiness Not Assessed (Awaiting source status)</div>
          )}
        </div>

        {/* B. Live Security Monitoring Status */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Activity size={16} className="text-teal" />
              Live Security Telemetry & Collector
            </span>
            <span className={`badge ${isVmOnline ? 'badge-teal' : 'badge-neutral'}`}>
              <span className={`pulse-indicator dot-sm ${isVmOnline ? '' : 'pulse-red'}`}></span>
              VM {isVmOnline ? 'CONNECTED' : 'WAITING'}
            </span>
          </div>

          <div className="grid-2" style={{ gap: 'var(--space-3)', marginBottom: '14px' }}>
            <div className="stat">
              <div className="label">Total Ingested Events</div>
              <div className="stat-value-lg">{events.length}</div>
              <div className="text-xs text-teal">{eventsInLast5Min} received in last 5m</div>
            </div>

            <div className="stat">
              <div className="label">Active Detections</div>
              <div className={`stat-value-lg ${openAlerts.length > 0 ? 'text-red' : ''}`}>{openAlerts.length}</div>
              <div className={`text-xs ${highSeverityAlerts.length > 0 ? 'text-red' : 'text-muted'}`}>
                {highSeverityAlerts.length} high/critical severity
              </div>
            </div>
          </div>

          <div className="stack-sm text-sm text-secondary" style={{ gap: 'var(--space-1)' }}>
            <div className="kv-row text-sm">
              <span>Collector Host:</span>
              {collector ? (
                <span className="mono text-primary">{collector.hostname} ({collector.ip_address})</span>
              ) : (
                <span className="text-muted">No collector registered</span>
              )}
            </div>
            <div className="kv-row text-sm">
              <span>Agent Protocol:</span>
              <span className="mono">HTTP/1.1 Ingestion API (Key Authenticated, SHA-256 Deduplicated)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row: Active Incident & MITRE ATT&CK Intelligence */}
      <div className="grid-2">
        {/* Incident Overview Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <AlertTriangle size={16} className={openAlerts.length > 0 ? 'text-red' : 'text-teal'} />
              Active Incident Response Case
            </span>
            {activeCase ? (
              <span className="badge badge-amber">{activeCase.case_id}</span>
            ) : (
              <span className="badge badge-neutral">NO ACTIVE INCIDENT</span>
            )}
          </div>

          {activeCase ? (
            <div>
              <div className="strong" style={{ fontSize: '13px', marginBottom: '6px' }}>{activeCase.title}</div>
              <p className="text-md text-secondary prose" style={{ marginBottom: 'var(--space-2)' }}>
                {activeCase.summary}
              </p>

              <div className="row-sm wrap" style={{ marginBottom: 'var(--space-3)' }}>
                <span className="badge badge-teal">{activeCase.status}</span>
                <span className={`badge ${severityBadge(activeCase.severity)}`}>{activeCase.severity}</span>
                <span className="badge badge-neutral">{activeCase.supporting_event_ids?.length || 0} events</span>
                <span className="badge badge-neutral">{activeCase.supporting_alert_ids?.length || 0} alerts</span>
                <span className="badge badge-neutral">
                  Readiness at detection {activeCase.readiness_score_at_time.toFixed(1)}%
                </span>
              </div>

              {nextAction && (
                <div className="panel panel-accent" style={{ marginBottom: '14px' }}>
                  <div className="eyebrow" style={{ fontSize: 'var(--fs-2xs)', marginBottom: '3px' }}>
                    {nextAction.label}
                  </div>
                  <div className="text-md text-primary">{nextAction.text}</div>
                  {nextAction.remainingQuestions > 0 && (
                    <div className="text-xs text-muted" style={{ marginTop: 'var(--space-1)' }}>
                      +{nextAction.remainingQuestions} unresolved question{nextAction.remainingQuestions === 1 ? '' : 's'} on this case
                    </div>
                  )}
                </div>
              )}

              <div className="row-lg">
                <button className="btn btn-primary" onClick={() => onNavigate('investigation')}>
                  <FileText size={13} />
                  Open Case Investigation
                </button>
                <button className="btn btn-secondary" onClick={() => onNavigate('prioritization')}>
                  Run Evidence Prioritization <ArrowRight size={12} />
                </button>
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <ShieldCheck size={32} className="empty-state-icon" style={{ color: 'var(--teal-core)' }} />
              <div>Target environment operating within baseline parameters.</div>
              <div className="empty-state-hint">No active security alerts or brute-force anomalies detected.</div>
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Context Card — driven by live alerts / the open case */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Layers size={16} className="text-teal" />
              Threat Context (MITRE ATT&CK Enterprise)
            </span>
            {activeThreat ? (
              <span className={`badge ${activeThreat.origin === 'alert' ? 'badge-red' : 'badge-amber'}`}>
                {activeThreat.techniqueId} PRIMARY
              </span>
            ) : (
              <span className="badge badge-neutral">NO ACTIVE TECHNIQUE</span>
            )}
          </div>

          {activeThreat ? (
            <div className="stack">
              <div className="panel">
                <div className="row-between" style={{ marginBottom: 'var(--space-1)' }}>
                  <span className="mono text-teal" style={{ fontWeight: 600, fontSize: '13px' }}>
                    {activeThreat.techniqueId}: {techniqueName}
                  </span>
                  {tactic && <span className="badge badge-neutral">{tactic}</span>}
                </div>
                <p className="text-md text-secondary clamp-3" style={{ lineHeight: 1.45 }} title={technique?.description}>
                  {technique?.description ?? leadAlert?.explanation ?? 'No ATT&CK description available for this technique.'}
                </p>
              </div>

              <div className="kv-row">
                <span>Observed Activity:</span>
                <span className="mono text-primary">
                  {activeThreat.origin === 'alert'
                    ? `${activeThreat.alerts.length} alert${activeThreat.alerts.length === 1 ? '' : 's'} · ${threatEventCount} events`
                    : `Open case ${activeCase?.case_id ?? ''}`}
                </span>
              </div>

              {threatSeverity && (
                <div className="kv-row">
                  <span>Highest Severity:</span>
                  <span className={`badge ${severityBadge(threatSeverity)}`}>{threatSeverity}</span>
                </div>
              )}

              {leadAlert && (leadAlert.source_ip || leadAlert.target_user) && (
                <div className="kv-row">
                  <span>Source → Target:</span>
                  <span className="mono text-primary">
                    {leadAlert.source_ip || 'unknown'} → {leadAlert.target_user || 'unknown'}@{leadAlert.source_host}
                  </span>
                </div>
              )}

              {lastObserved && (
                <div className="kv-row">
                  <span>Last Observed:</span>
                  <span className="mono">{parseServerTime(lastObserved).toLocaleString()}</span>
                </div>
              )}

              {technique && technique.evidence_sources.length > 0 && (
                <div>
                  <div className="kv-row" style={{ marginBottom: '6px' }}>
                    <span>Evidence Sources (per ATT&CK):</span>
                  </div>
                  <div className="row-sm wrap">
                    {technique.evidence_sources.map((src) => (
                      <span key={src} className="badge badge-teal badge-sm">{src}</span>
                    ))}
                  </div>
                </div>
              )}

              {activeThreat.otherTechniqueIds.length > 0 && (
                <div className="kv-row">
                  <span>Also Active:</span>
                  <span className="row-sm wrap" style={{ justifyContent: 'flex-end' }}>
                    {activeThreat.otherTechniqueIds.map((id) => (
                      <span key={id} className="badge badge-neutral mono">{id}</span>
                    ))}
                  </span>
                </div>
              )}

              <button
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigate('detection')}
                style={{ alignSelf: 'flex-start', marginTop: 'var(--space-1)' }}
              >
                Browse Complete ATT&CK Matrix <ArrowRight size={12} />
              </button>
            </div>
          ) : (
            <div className="empty-state">
              <ShieldCheck size={32} className="empty-state-icon" style={{ color: 'var(--teal-core)' }} />
              <div>No active ATT&CK techniques observed.</div>
              <div className="empty-state-hint">Threat context appears here once a detection rule fires.</div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigate('detection')}
                style={{ marginTop: 'var(--space-3)' }}
              >
                Browse ATT&CK Matrix <ArrowRight size={12} />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Bottom Section: Live Activity Telemetry Feed */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Clock size={16} className="text-teal" />
            Live Monitored Telemetry Stream ({events.length} observed events)
          </span>
          <span className="badge badge-neutral">Chronological Order</span>
        </div>

        {events.length > 0 ? (
          <div className="data-table-container table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Host</th>
                  <th>Source</th>
                  <th>Event Type</th>
                  <th>User</th>
                  <th>Source IP</th>
                  <th>Raw Message Summary</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 15).map((evt) => {
                  const isFail = evt.event_type === 'ssh_auth_failure';
                  return (
                    <tr key={evt.event_id}>
                      <td className="mono cell-small">
                        {parseServerTime(evt.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="mono text-primary">{evt.host}</td>
                      <td><span className="badge badge-neutral">{evt.source}</span></td>
                      <td>
                        <span className={`badge ${isFail ? 'badge-red' : 'badge-neutral'}`}>{evt.event_type}</span>
                      </td>
                      <td className={`mono ${evt.user === 'root' ? 'text-red' : 'text-primary'}`}>
                        {evt.user || 'N/A'}
                      </td>
                      <td className="mono">{evt.source_ip || 'N/A'}</td>
                      <td className="truncate" style={{ maxWidth: '360px' }} title={evt.message}>
                        {evt.message}
                      </td>
                      <td>
                        <button className="btn btn-secondary btn-sm" onClick={() => setSelectedEvent(evt)}>
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            Awaiting live telemetry stream. Start the Ubuntu collector agent (python3 threxis_collector.py) to stream real network events directly to THREXIS.
          </div>
        )}
      </div>

      {/* Inspect Event Modal */}
      {selectedEvent && (
        <div className="modal-backdrop" onClick={() => setSelectedEvent(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">Event Inspection: {selectedEvent.event_id}</span>
              <button className="btn btn-secondary" onClick={() => setSelectedEvent(null)}>Close</button>
            </div>

            <div className="modal-body" style={{ gap: 'var(--space-2)' }}>
              <div><b>Host:</b> {selectedEvent.host}</div>
              <div><b>Timestamp:</b> {selectedEvent.timestamp}</div>
              <div><b>Event Type:</b> <span className="badge badge-amber">{selectedEvent.event_type}</span></div>
              <div><b>Target User:</b> {selectedEvent.user || 'N/A'}</div>
              <div><b>Source IP:</b> {selectedEvent.source_ip || 'N/A'} (Port {selectedEvent.source_port || 'N/A'})</div>
              <div>
                <b>SHA-256 Provenance Hash:</b>{' '}
                <span className="mono text-teal text-xs">{selectedEvent.sha256}</span>
              </div>
              <div style={{ marginTop: 'var(--space-2)' }}><b>Raw Log Line:</b></div>
              <pre className="code-block text-primary" style={{ padding: '10px' }}>{selectedEvent.raw_log}</pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
