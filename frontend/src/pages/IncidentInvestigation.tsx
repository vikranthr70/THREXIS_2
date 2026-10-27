import React, { useState, useEffect, useRef } from 'react';
import {
  FileSearch, Download, FileText, Clock, Save, CheckCircle2, HelpCircle,
  Vault, ArrowRight, Eye, Lock, RotateCcw, ChevronRight
} from 'lucide-react';
import type { InvestigationCase, TimelineItem, EvidenceVaultItem } from '../types';
import { api } from '../services/api';
import { parseServerTime } from '../utils/time';

interface IncidentInvestigationProps {
  cases: InvestigationCase[];
  activeCase: InvestigationCase | null;
  vaultItems: EvidenceVaultItem[];
  onRefresh: () => void;
  onNavigateToVault: () => void;
}

const STATUS_LABEL: Record<string, string> = {
  ACTIVE: 'Active',
  UNDER_REVIEW: 'Under Review',
  PRESERVED: 'Preserved',
  CLOSED: 'Closed'
};

const fmtTime = (ts: string) =>
  parseServerTime(ts).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
  });

type TimelineEntry =
  | { kind: 'single'; item: TimelineItem }
  | { kind: 'group'; key: string; items: TimelineItem[] };

/**
 * Collapses runs of near-identical security events (same type, user, IP and host)
 * into one entry, so 500 failed logins read as one line instead of 500 rows and
 * the detection alert stays visible.
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

  // Refetch only when the selected case changes or the case itself was updated. The old
  // version refetched on every 3-second dashboard poll and overwrote the notes box.
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
        // New case, or no unsaved edits: show what's stored.
        setNotes(serverNotes);
        setSavedNotes(serverNotes);
      }
      // Otherwise keep the analyst's unsaved text untouched.
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
      setSelectedCaseId(caseId); // keep viewing this case even after it stops being "active"
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
        <FileSearch size={40} className="empty-state-icon text-muted" style={{ marginBottom: 'var(--space-3)' }} />
        <div className="page-empty-title">No Incident Cases Opened</div>
        <div className="page-empty-hint">
          When security detections occur, THREXIS automatically opens a threat-informed forensic investigation case.
        </div>
      </div>
    );
  }

  const c = selectedCase;
  const timeline: TimelineItem[] = caseDetail?.timeline || [];
  const entries = groupTimeline(timeline);
  const isHighSeverity = c.severity === 'CRITICAL' || c.severity === 'HIGH';
  const caseEvidence = vaultItems.filter((v) => v.case_id === c.case_id);
  const openCount = cases.filter((x) => x.status !== 'CLOSED').length;
  const isDirty = notes !== savedNotes;

  return (
    <div className="page-container page-stack">

      {/* Case switcher — every case is reachable, not just the latest one */}
      {cases.length > 1 && (
        <div className="card row-between wrap" style={{ padding: 'var(--space-3) var(--space-4)' }}>
          <div className="row wrap">
            <label className="label" htmlFor="case-select">Case</label>
            <select
              id="case-select"
              className="form-control form-control-sm"
              style={{ minWidth: '420px' }}
              value={c.case_id}
              onChange={(e) => setSelectedCaseId(e.target.value)}
            >
              {cases.map((x) => (
                <option key={x.case_id} value={x.case_id}>
                  {x.case_id} · {STATUS_LABEL[x.status] ?? x.status} · {x.title}
                </option>
              ))}
            </select>
          </div>
          <span className="text-sm text-muted">{cases.length} cases · {openCount} open</span>
        </div>
      )}

      {/* Top Banner: Case Summary, Status Actions & Exports */}
      <div className={`card ${c.status === 'CLOSED' ? 'card-accent' : 'card-accent-amber'}`}>
        <div className="hero-row">
          <div>
            <div className="row">
              <span className="mono badge badge-amber" style={{ fontSize: 'var(--fs-base)' }}>{c.case_id}</span>
              <span className={`badge ${isHighSeverity ? 'badge-red' : 'badge-neutral'}`}>{c.severity} SEVERITY</span>
              <span className={`badge ${c.status === 'CLOSED' ? 'badge-neutral' : 'badge-teal'}`}>
                {(STATUS_LABEL[c.status] ?? c.status).toUpperCase()}
              </span>
            </div>
            <h2 className="hero-title" style={{ marginTop: '6px' }}>{c.title}</h2>
            <p className="hero-desc">{c.summary}</p>
          </div>

          <div className="stack-sm" style={{ alignItems: 'flex-end' }}>
            <div className="row-sm">
              {c.status === 'ACTIVE' && (
                <button className="btn btn-secondary" disabled={changingStatus} onClick={() => handleStatus('UNDER_REVIEW')}>
                  <Eye size={13} /> Mark Under Review
                </button>
              )}
              {c.status !== 'CLOSED' ? (
                <button
                  className="btn btn-secondary"
                  disabled={changingStatus}
                  onClick={() => handleStatus('CLOSED')}
                  title="Closing the case also closes its alerts, so the dashboard returns to baseline threat context."
                >
                  <Lock size={13} /> Close Case
                </button>
              ) : (
                <button className="btn btn-secondary" disabled={changingStatus} onClick={() => handleStatus('ACTIVE')}>
                  <RotateCcw size={13} /> Reopen Case
                </button>
              )}
            </div>
            <div className="row-sm">
              <a
                href={api.getReportDownloadUrl(c.case_id, 'pdf')}
                download={`THREXIS_Investigation_Report_${c.case_id}.pdf`}
                className="btn btn-primary"
              >
                <Download size={13} /> Export PDF Report
              </a>
              <a
                href={api.getReportDownloadUrl(c.case_id, 'json')}
                download={`THREXIS_Investigation_Report_${c.case_id}.json`}
                className="btn btn-secondary"
              >
                <FileText size={13} /> Export JSON
              </a>
            </div>
          </div>
        </div>

        {/* Case Metadata Details */}
        <div className="panel-inset meta-strip">
          <div><b>Primary Technique:</b> <span className="mono text-teal">{c.primary_technique}</span></div>
          <div><b>Opened:</b> <span className="mono">{fmtTime(c.created_at)}</span></div>
          <div>
            <b>Readiness When Opened:</b>{' '}
            <span className="mono strong">{c.readiness_score_at_time.toFixed(1)}%</span>
          </div>
          <div>
            <b>Supporting:</b>{' '}
            <span className="mono">
              {c.supporting_alert_ids?.length || 0} alerts · {c.supporting_event_ids?.length || 0} events
            </span>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={onNavigateToVault}>
            <Vault size={12} /> {caseEvidence.length} evidence item{caseEvidence.length === 1 ? '' : 's'} in Vault <ArrowRight size={12} />
          </button>
        </div>
      </div>

      {/* Investigation Timeline (repeated events grouped) */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Clock size={16} className="text-teal" />
            Investigation Timeline ({timeline.length} items)
          </span>
          <span className="text-sm text-muted">Repeated events are grouped · click to expand</span>
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
                      <summary className="row-lg wrap">
                        <ChevronRight size={13} className="timeline-chevron text-muted" />
                        <span className="mono text-sm text-muted">{fmtTime(first.timestamp)} – {fmtTime(last.timestamp)}</span>
                        <span className="badge badge-neutral badge-xs">SECURITY_EVENT ×{entry.items.length}</span>
                        <span className="strong" style={{ fontSize: '12.5px' }}>
                          {entry.items.length}× {eventType(first)} for '{first.user || 'unknown'}' from {first.source_ip || 'unknown IP'}
                        </span>
                      </summary>
                      <div className="stack-sm" style={{ marginTop: 'var(--space-2)', paddingLeft: '22px' }}>
                        {entry.items.map((it) => (
                          <div key={it.id}>
                            <div className="text-md text-secondary">
                              <span className="mono text-muted">{fmtTime(it.timestamp)}</span> · {it.description}
                            </div>
                            {it.sha256 && (
                              <div className="mono text-muted" style={{ fontSize: 'var(--fs-2xs)' }}>SHA-256: {it.sha256}</div>
                            )}
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
                  <div className="row-lg wrap">
                    <span className="mono text-sm text-muted">{fmtTime(item.timestamp)}</span>
                    <span className={`badge badge-xs ${isAlert ? 'badge-red' : isVault ? 'badge-teal' : 'badge-neutral'}`}>
                      {item.type}
                    </span>
                    <span className="strong" style={{ fontSize: '12.5px' }}>
                      {item.type === 'SECURITY_EVENT' ? `${eventType(item)} for '${item.user || 'unknown'}'` : item.title}
                    </span>
                    {item.technique && <span className="mono text-sm text-teal">{item.technique}</span>}
                  </div>
                  <div className="text-md text-secondary" style={{ paddingLeft: '2px' }}>{item.description}</div>
                  {item.sha256 && (
                    <div className="mono text-muted" style={{ fontSize: 'var(--fs-2xs)' }}>SHA-256: {item.sha256}</div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="empty-state">{caseDetail ? 'No correlated timeline items yet.' : 'Loading case timeline…'}</div>
        )}
      </div>

      {/* Findings & Open Questions */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <CheckCircle2 size={16} className="text-teal" />
              Forensic Findings
            </span>
            <span className="text-sm text-muted">Computed from stored alerts &amp; telemetry</span>
          </div>
          <div className="fact-list">
            {c.findings?.map((f, i) => {
              const isCompromise = f.startsWith('SUCCESSFUL');
              return (
                <div key={i} className={`fact-item ${isCompromise ? 'text-red' : ''}`}>
                  <span className={`fact-marker ${isCompromise ? 'text-red' : 'text-teal'}`}>{isCompromise ? '!' : '•'}</span>
                  <span>{f}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <HelpCircle size={16} className="text-amber" />
              Open Investigative Questions
            </span>
            <span className="text-sm text-muted">Prompts for the analyst, not findings</span>
          </div>
          <div className="fact-list">
            {c.unresolved_questions?.map((q, i) => (
              <div key={i} className="fact-item">
                <span className="fact-marker text-amber">?</span>
                <span>{q}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Analyst Notes Editor */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <FileText size={16} className="text-teal" />
            Analyst Working Notes
          </span>
          <div className="row-sm">
            {isDirty && <span className="text-sm text-amber">Unsaved changes</span>}
            <button className="btn btn-primary btn-sm" onClick={handleSaveNotes} disabled={savingNotes || !isDirty}>
              <Save size={12} />
              {savingNotes ? 'Saving...' : 'Save Notes'}
            </button>
          </div>
        </div>

        <textarea
          className="form-control"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          rows={5}
          placeholder="Document observations, hypothesis testing and actions taken. A line starting with “Recommended Action:” is shown as the next action on the Command Center."
        />

        {saveSuccess && (
          <div className="text-md text-teal" style={{ marginTop: 'var(--space-2)' }}>
            Analyst notes saved to the case record.
          </div>
        )}
      </div>

    </div>
  );
};
