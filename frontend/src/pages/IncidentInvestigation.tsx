import React, { useState, useEffect, useRef } from 'react';
import { FileSearch, Download, Save, Vault, Eye, Lock, RotateCcw, ChevronRight } from 'lucide-react';
import type { InvestigationCase, TimelineItem, EvidenceVaultItem } from '../types';
import { api } from '../services/api';
import { parseServerTime } from '../utils/time';
import { Chip, StatusDot } from '../components/ui';
import { labelize, severityTone } from '../utils/format';

interface IncidentInvestigationProps {
  cases: InvestigationCase[];
  activeCase: InvestigationCase | null;
  vaultItems: EvidenceVaultItem[];
  onRefresh: () => void;
  onNavigateToVault: () => void;
}

const fmtTime = (ts: string) =>
  parseServerTime(ts).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
  });

const caseStatusTone = (status: string) => (status === 'CLOSED' ? 'muted' : status === 'ACTIVE' ? 'warn' : 'neutral');

type TimelineEntry =
  | { kind: 'single'; item: TimelineItem }
  | { kind: 'group'; key: string; items: TimelineItem[] };

/**
 * Collapses runs of near-identical security events (same type, user, IP and host)
 * into one entry, so 500 failed logins read as one line and alerts stay visible.
 */
function groupTimeline(items: TimelineItem[]): TimelineEntry[] {
  const out: TimelineEntry[] = [];
  for (const item of items) {
    const last = out[out.length - 1];
    if (item.type === 'SECURITY_EVENT') {
      const key = [item.title, item.user, item.source_ip, item.host].join('|');
      if (last?.kind === 'group' && last.key === key) {
        last.items.push(item);
        continue;
      }
      out.push({ kind: 'group', key, items: [item] });
    } else {
      out.push({ kind: 'single', item });
    }
  }
  return out.map((e) => (e.kind === 'group' && e.items.length === 1 ? { kind: 'single', item: e.items[0] } : e));
}

const eventType = (item: TimelineItem) => item.title.replace(/^Security Event:\s*/, '');

export const IncidentInvestigation: React.FC<IncidentInvestigationProps> = ({
  cases,
  activeCase,
  vaultItems,
  onRefresh,
  onNavigateToVault
}) => {
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const selectedCase =
    cases.find((c) => c.case_id === selectedCaseId) ?? activeCase ?? cases[0] ?? null;
  const caseId = selectedCase?.case_id ?? null;
  const updatedAt = selectedCase?.updated_at ?? null;

  const [caseDetail, setCaseDetail] = useState<any>(null);
  const [notes, setNotes] = useState<string>('');
  const [savedNotes, setSavedNotes] = useState<string>('');
  const [savingNotes, setSavingNotes] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);
  const [changingStatus, setChangingStatus] = useState<boolean>(false);

  // Refs let the fetch callback see the latest editor state without re-running the effect.
  const loadedCaseRef = useRef<string | null>(null);
  const notesRef = useRef(notes);
  const savedNotesRef = useRef(savedNotes);
  useEffect(() => {
    notesRef.current = notes;
    savedNotesRef.current = savedNotes;
  }, [notes, savedNotes]);

  // Refetch only when the selected case changes or the case itself was updated,
  // and never overwrite unsaved notes.
  useEffect(() => {
    if (!caseId) return;
    let cancelled = false;
    const switchingCase = loadedCaseRef.current !== caseId;
    if (switchingCase) setCaseDetail(null);

    api.getCaseDetail(caseId).then((data) => {
      if (cancelled) return;
      setCaseDetail(data);
      const serverNotes: string = data.case.analyst_notes || '';
      const isClean = notesRef.current === savedNotesRef.current;
      if (switchingCase || isClean) {
        setNotes(serverNotes);
        setSavedNotes(serverNotes);
      }
      loadedCaseRef.current = caseId;
    }).catch(console.error);

    return () => { cancelled = true; };
  }, [caseId, updatedAt]);

  const handleSaveNotes = async () => {
    if (!caseId) return;
    setSavingNotes(true);
    try {
      await api.updateCaseNotes(caseId, notes);
      setSavedNotes(notes);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setSavingNotes(false);
    }
  };

  const handleStatus = async (status: string) => {
    if (!caseId) return;
    setChangingStatus(true);
    try {
      await api.updateCaseStatus(caseId, status);
      setSelectedCaseId(caseId);
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setChangingStatus(false);
    }
  };

  if (!selectedCase) {
    return (
      <div className="page-container page-empty">
        <FileSearch size={32} />
        <div className="page-empty-title">No investigation cases</div>
        <div className="page-empty-hint">A case opens automatically when a detection rule fires.</div>
      </div>
    );
  }

  const c = selectedCase;
  const timeline: TimelineItem[] = caseDetail?.timeline || [];
  const entries = groupTimeline(timeline);
  const caseEvidence = vaultItems.filter((v) => v.case_id === c.case_id);
  const openCount = cases.filter((x) => x.status !== 'CLOSED').length;
  const isDirty = notes !== savedNotes;

  return (
    <div className="page-container page-stack">

      {/* Case header */}
      <div className="card">
        <div className="card-header">
          <div className="row grow">
            {cases.length > 1 ? (
              <select
                className="form-control form-control-sm"
                aria-label="Select case"
                style={{ maxWidth: 520 }}
                value={c.case_id}
                onChange={(e) => setSelectedCaseId(e.target.value)}
              >
                {cases.map((x) => (
                  <option key={x.case_id} value={x.case_id}>
                    {x.case_id} · {labelize(x.status)} · {x.title}
                  </option>
                ))}
              </select>
            ) : (
              <span className="card-meta">{c.case_id}</span>
            )}
            <span className="card-meta">{cases.length} case{cases.length === 1 ? '' : 's'} · {openCount} open</span>
          </div>
          <div className="row">
            {c.status === 'ACTIVE' && (
              <button className="btn btn-secondary btn-sm" disabled={changingStatus} onClick={() => handleStatus('UNDER_REVIEW')}>
                <Eye size={12} /> Mark under review
              </button>
            )}
            {c.status !== 'CLOSED' ? (
              <button
                className="btn btn-secondary btn-sm"
                disabled={changingStatus}
                onClick={() => handleStatus('CLOSED')}
                title="Also closes the case's alerts, so the dashboard returns to baseline threat context."
              >
                <Lock size={12} /> Close case
              </button>
            ) : (
              <button className="btn btn-secondary btn-sm" disabled={changingStatus} onClick={() => handleStatus('ACTIVE')}>
                <RotateCcw size={12} /> Reopen
              </button>
            )}
            <div className="divider-v" />
            <a href={api.getReportDownloadUrl(c.case_id, 'pdf')} download={`THREXIS_Investigation_Report_${c.case_id}.pdf`} className="btn btn-ghost btn-sm">
              <Download size={12} /> PDF
            </a>
            <a href={api.getReportDownloadUrl(c.case_id, 'json')} download={`THREXIS_Investigation_Report_${c.case_id}.json`} className="btn btn-ghost btn-sm">
              <Download size={12} /> JSON
            </a>
          </div>
        </div>

        <div className="card-body stack-lg">
          <div className="stack">
            <h2 className="strong" style={{ fontSize: 16 }}>{c.title}</h2>
            <div className="meta">
              <StatusDot tone={caseStatusTone(c.status)}>{labelize(c.status)}</StatusDot>
              <Chip tone={severityTone(c.severity)}>{c.severity}</Chip>
              <span>Technique <Chip tone="tag">{c.primary_technique}</Chip></span>
              <span>Opened <span className="mono">{fmtTime(c.created_at)}</span></span>
              <span><b className="num">{c.supporting_alert_ids?.length || 0}</b> alerts · <b className="num">{c.supporting_event_ids?.length || 0}</b> events</span>
              <span>Readiness at open <b className="num">{c.readiness_score_at_time.toFixed(1)}%</b></span>
            </div>
          </div>
          <p className="text-sm text-secondary prose" style={{ maxWidth: 900 }}>{c.summary}</p>
        </div>
        <div className="card-footer row-between">
          <span className="text-sm text-secondary">
            <span className="num">{caseEvidence.length}</span> evidence item{caseEvidence.length === 1 ? '' : 's'} preserved for this case
          </span>
          <button className="btn btn-ghost btn-sm" onClick={onNavigateToVault}><Vault size={12} /> Open Vault</button>
        </div>
      </div>

      {/* Findings & questions */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Findings</span>
            <span className="card-meta">Computed from alerts and telemetry</span>
          </div>
          <div className="list">
            {c.findings?.map((f, i) => {
              const isCompromise = f.startsWith('SUCCESSFUL');
              return (
                <div key={i} className="list-row text-sm">
                  {isCompromise
                    ? <StatusDot tone="crit"><span className="text-crit" style={{ whiteSpace: 'normal' }}>{f}</span></StatusDot>
                    : <span className="prose">{f}</span>}
                </div>
              );
            })}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Open questions</span>
            <span className="card-meta">For the analyst to answer</span>
          </div>
          <div className="list">
            {c.unresolved_questions?.length ? c.unresolved_questions.map((q, i) => (
              <div key={i} className="list-row text-sm prose">{q}</div>
            )) : <div className="list-row text-sm text-muted">None.</div>}
          </div>
        </div>
      </div>

      {/* Timeline */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Timeline</span>
          <span className="card-meta">{timeline.length} items · repeated events grouped</span>
        </div>

        {entries.length > 0 ? (
          <div className="timeline">
            {entries.map((entry) => {
              if (entry.kind === 'group') {
                const first = entry.items[0];
                const last = entry.items[entry.items.length - 1];
                return (
                  <div key={first.id} className="timeline-item">
                    <div className="timeline-dot" />
                    <details className="timeline-group">
                      <summary className="row wrap">
                        <ChevronRight size={13} className="timeline-chevron text-muted" />
                        <span className="text-heading medium">
                          <span className="num">{entry.items.length}</span>× {eventType(first)}
                        </span>
                        <span className="text-sm text-secondary">
                          {first.user || 'unknown'} from <span className="mono">{first.source_ip || 'unknown'}</span>
                        </span>
                        <span className="mono text-muted">{fmtTime(first.timestamp)} – {fmtTime(last.timestamp)}</span>
                      </summary>
                      <div className="stack" style={{ marginTop: 8, paddingLeft: 21, gap: 6 }}>
                        {entry.items.map((it) => (
                          <div key={it.id} className="text-sm">
                            <span className="mono text-muted">{fmtTime(it.timestamp)}</span>
                            <span className="text-secondary"> {it.description}</span>
                            {it.sha256 && <div className="mono text-muted" style={{ fontSize: 11 }}>{it.sha256}</div>}
                          </div>
                        ))}
                      </div>
                    </details>
                  </div>
                );
              }
              const item = entry.item;
              const isAlert = item.type === 'DETECTION_ALERT';
              const isVault = item.type === 'EVIDENCE_ACQUIRED';
              return (
                <div key={item.id} className="timeline-item">
                  <div className={`timeline-dot ${isAlert ? 'is-alert' : isVault ? 'is-vault' : ''}`} />
                  <div className="row wrap">
                    <span className="text-heading medium">
                      {item.type === 'SECURITY_EVENT' ? `${eventType(item)} · ${item.user || 'unknown'}` : item.title}
                    </span>
                    {item.technique && <Chip tone="tag">{item.technique.split(' - ')[0]}</Chip>}
                    {isAlert && item.severity && <Chip tone={severityTone(item.severity)}>{item.severity}</Chip>}
                    <span className="mono text-muted">{fmtTime(item.timestamp)}</span>
                  </div>
                  <div className="text-sm text-secondary">{item.description}</div>
                  {item.sha256 && <div className="mono text-muted" style={{ fontSize: 11 }}>{item.sha256}</div>}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="empty-state">{caseDetail ? 'No timeline items yet.' : 'Loading timeline…'}</div>
        )}
      </div>

      {/* Notes */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Analyst notes</span>
          <div className="row">
            {isDirty && <span className="text-sm text-warn">Unsaved changes</span>}
            {saveSuccess && !isDirty && <span className="text-sm text-secondary">Saved</span>}
            <button className="btn btn-primary btn-sm" onClick={handleSaveNotes} disabled={savingNotes || !isDirty}>
              <Save size={12} /> {savingNotes ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
        <div className="card-body">
          <textarea
            className="form-control"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={5}
            placeholder="Observations, hypotheses and actions taken. A line starting with “Recommended Action:” appears as the next action on the Command Center."
          />
        </div>
      </div>
    </div>
  );
};
