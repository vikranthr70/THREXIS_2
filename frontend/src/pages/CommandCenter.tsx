import React, { useState } from 'react';
import { ArrowRight, BookOpen } from 'lucide-react';
import type {
  ReadinessAssessment,
  SecurityEvent,
  DetectionAlert,
  InvestigationCase,
  MitreTechnique
} from '../types';
import { ReadinessWeightingBadge } from '../components/ReadinessWeightingBadge';
import { MethodologyDrawer } from '../components/MethodologyDrawer';
import { Chip, InfoTip, StatusDot } from '../components/ui';
import {
  type ActiveThreat,
  deriveNextAction,
  findTechnique,
  isOpenStatus,
  severityRank
} from '../utils/threatContext';
import { labelize, readinessTone, sentenceCase, severityTone } from '../utils/format';
import { parseServerTime } from '../utils/time';

interface CommandCenterProps {
  readiness: ReadinessAssessment | null;
  events: SecurityEvent[];
  alerts: DetectionAlert[];
  techniques: MitreTechnique[];
  activeThreat: ActiveThreat | null;
  activeCase: InvestigationCase | null;
  onNavigate: (tab: string) => void;
}

const segmentClass = (factor: number) => (factor >= 0.85 ? 'is-full' : factor > 0 ? 'is-partial' : 'is-empty');

const eventTone = (type: string) => (type === 'ssh_auth_failure' ? 'warn' : 'neutral');

export const CommandCenter: React.FC<CommandCenterProps> = ({
  readiness,
  events,
  alerts,
  techniques,
  activeThreat,
  activeCase,
  onNavigate
}) => {
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [methodologyOpen, setMethodologyOpen] = useState(false);

  const openAlerts = alerts.filter(a => isOpenStatus(a.status));
  const highSeverityAlerts = openAlerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL');
  const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
  const eventsInLast5Min = events.filter(e => parseServerTime(e.timestamp) >= fiveMinAgo).length;

  // Same definition as the backend's coverage_percentage (available/collected/validated).
  const coveredSources = readiness
    ? readiness.sources.filter(s => ['available', 'collected', 'validated'].includes(s.status)).length
    : 0;
  const missingSources = readiness ? readiness.sources.filter(s => s.factor === 0).length : 0;

  const nextAction = activeCase ? deriveNextAction(activeCase) : null;

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

      {/* KPI strip */}
      <div className="grid-4">
        <div className="card kpi">
          <div className="kpi-label">
            Forensic readiness
            <InfoTip label="How readiness is calculated">
              Weighted average of evidence sources: 100 × Σ(wᵢ·sᵢ) / Σ(wᵢ), where wᵢ is a source's investigative
              weight and sᵢ how usable it is. Open Methodology for details.
            </InfoTip>
          </div>
          {readiness ? (
            <>
              <div className={`kpi-value ${readinessTone(readiness.score) === 'crit' ? 'text-crit' : readinessTone(readiness.score) === 'warn' ? 'text-warn' : ''}`}>
                {readiness.score.toFixed(1)}%
              </div>
              <div className="kpi-sub">
                Score {readiness.weighted_sum.toFixed(2)} / {readiness.total_weight.toFixed(2)} · {sentenceCase(readiness.category)}
              </div>
              <div className="meter" style={{ marginTop: 10 }} aria-label="Readiness by source">
                {readiness.sources.map((s) => (
                  <div
                    key={s.source_key}
                    className={`meter-seg ${segmentClass(s.factor)}`}
                    title={`${s.source_name}: ${labelize(s.status)} (weight ${s.weight.toFixed(2)})`}
                    style={{ flex: s.weight }}
                  />
                ))}
              </div>
              <div className="row-between" style={{ marginTop: 8 }}>
                <ReadinessWeightingBadge readiness={readiness} />
                <button className="btn btn-ghost btn-sm" onClick={() => setMethodologyOpen(true)}>
                  <BookOpen size={12} /> Methodology
                </button>
              </div>
            </>
          ) : (
            <div className="kpi-sub">Not assessed yet</div>
          )}
        </div>

        <div className="card kpi">
          <div className="kpi-label">Evidence coverage</div>
          <div className="kpi-value">{readiness ? `${readiness.coverage_percentage}%` : '—'}</div>
          <div className="kpi-sub">
            {readiness ? (
              <>
                {coveredSources} of {readiness.sources.length} sources available
                {missingSources > 0 && <> · <span className="text-warn">{missingSources} missing</span></>}
              </>
            ) : '—'}
          </div>
        </div>

        <div className="card kpi">
          <div className="kpi-label">Open detections</div>
          <div className={`kpi-value ${openAlerts.length > 0 ? 'text-crit' : ''}`}>{openAlerts.length}</div>
          <div className="kpi-sub">
            {highSeverityAlerts.length > 0
              ? <span className="text-crit">{highSeverityAlerts.length} high or critical</span>
              : 'None high or critical'}
          </div>
        </div>

        <div className="card kpi">
          <div className="kpi-label">Events ingested</div>
          <div className="kpi-value">{events.length}</div>
          <div className="kpi-sub">{eventsInLast5Min} in the last 5 minutes</div>
        </div>
      </div>

      {/* Incident + threat context */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Active incident</span>
            {activeCase && <span className="card-meta">{activeCase.case_id}</span>}
          </div>

          {activeCase ? (
            <>
              <div className="card-body stack-lg">
                <div className="stack">
                  <div className="strong">{activeCase.title}</div>
                  <div className="meta">
                    <StatusDot tone={activeCase.status === 'ACTIVE' ? 'warn' : 'neutral'}>{labelize(activeCase.status)}</StatusDot>
                    <Chip tone={severityTone(activeCase.severity)}>{activeCase.severity}</Chip>
                    <span><b className="num">{activeCase.supporting_event_ids?.length || 0}</b> events</span>
                    <span><b className="num">{activeCase.supporting_alert_ids?.length || 0}</b> alerts</span>
                    <span>Readiness at open <b className="num">{activeCase.readiness_score_at_time.toFixed(1)}%</b></span>
                  </div>
                </div>
                <p className="text-sm text-secondary prose">{activeCase.summary}</p>
                {nextAction && (
                  <div>
                    <div className="section-label">
                      {nextAction.label.startsWith('Recommended') ? 'Next action · analyst notes' : 'Next action · open question'}
                    </div>
                    <div className="text-sm text-body">{nextAction.text}</div>
                    {nextAction.remainingQuestions > 0 && (
                      <div className="text-xs text-muted" style={{ marginTop: 2 }}>
                        +{nextAction.remainingQuestions} more open question{nextAction.remainingQuestions === 1 ? '' : 's'}
                      </div>
                    )}
                  </div>
                )}
              </div>
              <div className="card-footer row">
                <button className="btn btn-primary" onClick={() => onNavigate('investigation')}>Open investigation</button>
                <button className="btn btn-secondary" onClick={() => onNavigate('prioritization')}>Prioritize evidence</button>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">No open incidents</div>
              <div className="empty-state-hint">Cases open automatically when a detection rule fires.</div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Threat context</span>
            <span className="card-meta">MITRE ATT&CK Enterprise</span>
          </div>

          {activeThreat ? (
            <>
              <div className="card-body stack-lg">
                <div className="stack">
                  <div className="row wrap">
                    <Chip tone="tag">{activeThreat.techniqueId}</Chip>
                    <span className="strong">{techniqueName}</span>
                    {tactic && <span className="text-sm text-secondary">· {tactic}</span>}
                  </div>
                  {technique?.description && (
                    <p className="text-sm text-secondary prose clamp-2" title={technique.description}>{technique.description}</p>
                  )}
                </div>
                <dl className="kv">
                  <dt>Activity</dt>
                  <dd>
                    {activeThreat.origin === 'alert'
                      ? <><span className="num">{activeThreat.alerts.length}</span> alert{activeThreat.alerts.length === 1 ? '' : 's'} · <span className="num">{threatEventCount}</span> events</>
                      : <>From open case {activeCase?.case_id}</>}
                  </dd>
                  {threatSeverity && (<><dt>Severity</dt><dd><Chip tone={severityTone(threatSeverity)}>{threatSeverity}</Chip></dd></>)}
                  {leadAlert && (leadAlert.source_ip || leadAlert.target_user) && (
                    <>
                      <dt>Source → target</dt>
                      <dd>
                        <span className="mono">{leadAlert.source_ip || 'unknown'}</span>
                        {' → '}{leadAlert.target_user || 'unknown'}@{leadAlert.source_host}
                      </dd>
                    </>
                  )}
                  {lastObserved && (<><dt>Last observed</dt><dd className="mono">{parseServerTime(lastObserved).toLocaleString()}</dd></>)}
                  {technique && technique.evidence_sources.length > 0 && (
                    <><dt>Evidence sources</dt><dd className="text-secondary">{technique.evidence_sources.join(', ')}</dd></>
                  )}
                  {activeThreat.otherTechniqueIds.length > 0 && (
                    <>
                      <dt>Also active</dt>
                      <dd className="row wrap">{activeThreat.otherTechniqueIds.map((id) => <Chip key={id} tone="tag">{id}</Chip>)}</dd>
                    </>
                  )}
                </dl>
              </div>
              <div className="card-footer">
                <button className="btn btn-ghost btn-sm" onClick={() => onNavigate('detection')}>
                  Open ATT&CK explorer <ArrowRight size={12} />
                </button>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">No active ATT&CK technique</div>
              <div className="empty-state-hint">Context appears here once a detection rule fires.</div>
            </div>
          )}
        </div>
      </div>

      {/* Recent telemetry */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Recent telemetry</span>
          <span className="card-meta">{events.length} events · newest first</span>
        </div>

        {events.length > 0 ? (
          <div className="data-table-container table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Host</th>
                  <th>Source</th>
                  <th>User</th>
                  <th>Source IP</th>
                  <th>Message</th>
                  <th className="num">Time (UTC)</th>
                  <th className="actions"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 15).map((evt) => (
                  <tr key={evt.event_id}>
                    <td><StatusDot tone={eventTone(evt.event_type)}>{evt.event_type}</StatusDot></td>
                    <td>{evt.host}</td>
                    <td className="mono cell-secondary">{evt.source}</td>
                    <td>{evt.user || '—'}</td>
                    <td className="mono">{evt.source_ip || '—'}</td>
                    <td className="cell-secondary truncate" style={{ maxWidth: 340 }} title={evt.message}>{evt.message}</td>
                    <td className="num mono cell-secondary">
                      {parseServerTime(evt.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="actions">
                      <button className="btn btn-secondary btn-sm" onClick={() => setSelectedEvent(evt)}>Inspect</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-title">No telemetry yet</div>
            <div className="empty-state-hint">Start the collector on the Ubuntu VM (python3 threxis_collector.py).</div>
          </div>
        )}
      </div>

      {selectedEvent && (
        <div className="modal-backdrop" onClick={() => setSelectedEvent(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">Event {selectedEvent.event_id}</span>
              <button className="btn btn-ghost btn-sm" onClick={() => setSelectedEvent(null)}>Close</button>
            </div>
            <div className="modal-body">
              <dl className="kv">
                <dt>Type</dt><dd><StatusDot tone={eventTone(selectedEvent.event_type)}>{selectedEvent.event_type}</StatusDot></dd>
                <dt>Host</dt><dd>{selectedEvent.host}</dd>
                <dt>Timestamp</dt><dd className="mono">{selectedEvent.timestamp}</dd>
                <dt>User</dt><dd>{selectedEvent.user || '—'}</dd>
                <dt>Source</dt><dd><span className="mono">{selectedEvent.source_ip || '—'}</span>{selectedEvent.source_port ? <span className="text-muted"> port {selectedEvent.source_port}</span> : null}</dd>
                <dt>SHA-256</dt><dd className="mono" style={{ wordBreak: 'break-all' }}>{selectedEvent.sha256}</dd>
              </dl>
              <div>
                <div className="section-label">Raw log line</div>
                <pre className="code-block">{selectedEvent.raw_log}</pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {methodologyOpen && readiness && (
        <MethodologyDrawer readiness={readiness} onClose={() => setMethodologyOpen(false)} />
      )}
    </div>
  );
};
