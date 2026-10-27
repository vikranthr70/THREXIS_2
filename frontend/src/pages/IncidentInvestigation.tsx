import React, { useState, useEffect } from 'react';
import { FileSearch, Download, FileText, Clock, Save, CheckCircle2, HelpCircle } from 'lucide-react';
import type { InvestigationCase, TimelineItem } from '../types';
import { api } from '../services/api';

interface IncidentInvestigationProps {
  activeCase: InvestigationCase | null;
  onRefresh: () => void;
  onNavigateToVault: () => void;
}

export const IncidentInvestigation: React.FC<IncidentInvestigationProps> = ({
  activeCase,
  onRefresh
}) => {
  const [caseDetail, setCaseDetail] = useState<any>(null);
  const [notes, setNotes] = useState<string>('');
  const [savingNotes, setSavingNotes] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);

  useEffect(() => {
    if (activeCase) {
      api.getCaseDetail(activeCase.case_id).then((data) => {
        setCaseDetail(data);
        setNotes(data.case.analyst_notes || '');
      }).catch(console.error);
    }
  }, [activeCase]);

  const handleSaveNotes = async () => {
    if (!activeCase) return;
    setSavingNotes(true);
    try {
      await api.updateCaseNotes(activeCase.case_id, notes);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setSavingNotes(false);
    }
  };

  if (!activeCase) {
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

  const timeline: TimelineItem[] = caseDetail?.timeline || [];
  const isHighSeverity = activeCase.severity === 'CRITICAL' || activeCase.severity === 'HIGH';

  return (
    <div className="page-container page-stack">

      {/* Top Banner: Case Summary & Download Actions */}
      <div className="card card-accent-amber">
        <div className="hero-row">
          <div>
            <div className="row">
              <span className="mono badge badge-amber" style={{ fontSize: 'var(--fs-base)' }}>{activeCase.case_id}</span>
              <span className={`badge ${isHighSeverity ? 'badge-red' : 'badge-neutral'}`}>{activeCase.severity} SEVERITY</span>
              <span className="badge badge-teal">{activeCase.status}</span>
            </div>
            <h2 className="hero-title" style={{ marginTop: '6px' }}>{activeCase.title}</h2>
            <p className="hero-desc">{activeCase.summary}</p>
          </div>

          {/* Export Report Buttons */}
          <div className="row-lg">
            <a
              href={api.getReportDownloadUrl(activeCase.case_id, 'pdf')}
              download={`THREXIS_Investigation_Report_${activeCase.case_id}.pdf`}
              className="btn btn-primary btn-lg"
            >
              <Download size={13} />
              Export Court-Admissible PDF
            </a>
            <a
              href={api.getReportDownloadUrl(activeCase.case_id, 'json')}
              download={`THREXIS_Investigation_Report_${activeCase.case_id}.json`}
              className="btn btn-secondary btn-lg"
            >
              <FileText size={13} />
              Export Structured JSON
            </a>
          </div>
        </div>

        {/* Case Metadata Details */}
        <div className="panel-inset meta-strip">
          <div><b>Mapped Technique:</b> <span className="mono text-teal">{activeCase.primary_technique}</span></div>
          <div><b>First Observed:</b> <span className="mono">{new Date(activeCase.created_at).toLocaleString()}</span></div>
          <div>
            <b>Readiness Score At Detection:</b>{' '}
            <span className="mono strong">{activeCase.readiness_score_at_time.toFixed(1)}%</span>
          </div>
          <div><b>Supporting Events:</b> <span className="mono">{activeCase.supporting_event_ids?.length || 0} events</span></div>
        </div>
      </div>

      {/* Investigation Timeline */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Clock size={16} className="text-teal" />
            Chronological Investigation Timeline ({timeline.length} Correlated Items)
          </span>
          <span className="badge badge-neutral">Event + Alert + Vault Synchronized</span>
        </div>

        {timeline.length > 0 ? (
          <div className="timeline">
            {timeline.map((item) => {
              const isAlert = item.type === 'DETECTION_ALERT';
              const isVault = item.type === 'EVIDENCE_ACQUIRED';
              return (
                <div key={item.id} className="timeline-item">
                  <div className={`timeline-dot ${isAlert ? 'is-alert' : isVault ? 'is-vault' : ''}`} />

                  <div className="row-lg">
                    <span className="mono text-sm text-muted">{new Date(item.timestamp).toLocaleTimeString()}</span>
                    <span className={`badge badge-xs ${isAlert ? 'badge-red' : isVault ? 'badge-teal' : 'badge-neutral'}`}>
                      {item.type}
                    </span>
                    <span className="strong" style={{ fontSize: '12.5px' }}>{item.title}</span>
                  </div>

                  <div className="text-md text-secondary" style={{ paddingLeft: '2px' }}>{item.description}</div>

                  {item.sha256 && (
                    <div className="mono text-muted" style={{ fontSize: 'var(--fs-2xs)' }}>
                      SHA-256 Provenance: {item.sha256}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="empty-state">{caseDetail ? 'No correlated timeline items yet.' : 'Loading case timeline…'}</div>
        )}
      </div>

      {/* Findings & Unresolved Questions */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <CheckCircle2 size={16} className="text-teal" />
              Forensic Findings
            </span>
            <span className="badge badge-teal">Verified Facts</span>
          </div>
          <div className="fact-list">
            {activeCase.findings?.map((f, i) => (
              <div key={i} className="fact-item">
                <span className="fact-marker text-teal">•</span>
                <span>{f}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <HelpCircle size={16} className="text-amber" />
              Unresolved Investigative Questions
            </span>
            <span className="badge badge-amber">Hypotheses</span>
          </div>
          <div className="fact-list">
            {activeCase.unresolved_questions?.map((q, i) => (
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
            Analyst Working Notes & Investigative Assessment
          </span>
          <button className="btn btn-primary btn-sm" onClick={handleSaveNotes} disabled={savingNotes}>
            <Save size={12} />
            {savingNotes ? 'Saving...' : 'Save Notes'}
          </button>
        </div>

        <textarea
          className="form-control"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          rows={5}
          placeholder="Document investigator observations, hypothesis testing, witness statements, or lateral movement verification..."
        />
        <div className="text-xs text-muted" style={{ marginTop: 'var(--space-1)' }}>
          Tip: a line starting with “Recommended Action:” is surfaced as the next investigative action on the Command Center.
        </div>

        {saveSuccess && (
          <div className="text-md text-teal" style={{ marginTop: 'var(--space-2)' }}>
            Analyst notes successfully committed to case manifest.
          </div>
        )}
      </div>

    </div>
  );
};
