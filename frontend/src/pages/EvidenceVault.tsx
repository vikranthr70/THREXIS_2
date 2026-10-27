import React, { useState } from 'react';
import { Vault, ShieldCheck, CheckCircle2, XCircle } from 'lucide-react';
import type { EvidenceVaultItem, InvestigationCase, AcquireSelectionResult } from '../types';
import { api } from '../services/api';
import { AcquisitionSummary } from '../components/AcquisitionSummary';
import type { PrioritizationContext } from '../utils/threatContext';

interface EvidenceVaultProps {
  vaultItems: EvidenceVaultItem[];
  activeCase: InvestigationCase | null;
  /** Same context and budget as the Evidence Prioritization page. */
  prioritizationContext: PrioritizationContext;
  budget: number;
  onRefresh: () => void;
}

const WORKFLOW_STEPS = [
  'Evidence Identified',
  'Telemetry Acquired',
  'SHA-256 Calculated',
  'Manifest Sealed',
  'Integrity Verified'
];

export const EvidenceVault: React.FC<EvidenceVaultProps> = ({
  vaultItems,
  activeCase,
  prioritizationContext,
  budget,
  onRefresh
}) => {
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [acquiring, setAcquiring] = useState<boolean>(false);
  const [acquisition, setAcquisition] = useState<AcquireSelectionResult | null>(null);

  const handleVerify = async (evidenceId: string) => {
    setVerifyingId(evidenceId);
    try {
      const res = await api.verifyIntegrity(evidenceId);
      setVerificationResult(res);
      onRefresh();
    } catch (err: any) {
      console.error(err);
    } finally {
      setVerifyingId(null);
    }
  };

  // Preserves what adaptive prioritization selects for the active threat within the
  // current budget, instead of always grabbing SSH telemetry. The server only creates
  // vault items for sources backed by real collector telemetry; the rest are reported.
  const handlePreserveForCase = async () => {
    if (!activeCase) return;
    setAcquiring(true);
    try {
      const res = await api.acquireSelection(activeCase.case_id, {
        budget,
        threatContext: prioritizationContext.value
      });
      setAcquisition(res);
      onRefresh();
    } catch (err: any) {
      console.error(err);
    } finally {
      setAcquiring(false);
    }
  };

  return (
    <div className="page-container page-stack">

      {/* Top Card: Forensic Integrity Workflow & Quick Acquire */}
      <div className="card card-accent">
        <div className="hero-row">
          <div>
            <div className="eyebrow">Forensic Preservation Standard</div>
            <h2 className="hero-title">Cryptographic Evidence Vault & Chain of Custody</h2>
            <div className="hero-desc">
              All acquired digital evidence artifacts are saved as bit-stream copies with immediate SHA-256 hash generation,
              stored in read-only vaults with signed JSON custody manifests to guarantee evidentiary admissibility.
            </div>
          </div>

          {activeCase && (
            <div className="stack-sm" style={{ alignItems: 'flex-end' }}>
              <button className="btn btn-primary btn-lg" onClick={handlePreserveForCase} disabled={acquiring}>
                <Vault size={14} />
                {acquiring ? 'Preserving Evidence...' : 'Preserve Prioritized Evidence for Active Case'}
              </button>
              <span className="text-xs text-muted">
                Adaptive selection · budget {budget} · context{' '}
                <span className="mono">{prioritizationContext.value}</span>
                {prioritizationContext.auto ? ' (auto)' : ' (manual)'}
              </span>
            </div>
          )}
        </div>

        {/* Workflow Diagram */}
        <div className="panel-inset step-strip">
          {WORKFLOW_STEPS.map((label, i) => {
            const isCurrent = i === 2;
            return (
              <React.Fragment key={label}>
                {i > 0 && <span className="step-arrow">→</span>}
                <div className={`step ${isCurrent ? 'is-current' : ''}`}>
                  <span className={`mono badge ${isCurrent ? 'badge-teal' : 'badge-neutral'}`}>{i + 1}</span> {label}
                </div>
              </React.Fragment>
            );
          })}
        </div>

        {acquisition && <AcquisitionSummary result={acquisition} onDismiss={() => setAcquisition(null)} />}
      </div>

      {/* Vault Items Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Vault size={16} className="text-teal" />
            Preserved Forensic Artifacts in Vault ({vaultItems.length} Registered Items)
          </span>
          <span className="badge badge-neutral">Immutable Filesystem Vault</span>
        </div>

        {vaultItems.length > 0 ? (
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Evidence ID</th>
                  <th>Linked Case</th>
                  <th>Source Title</th>
                  <th>Original Path</th>
                  <th>Records</th>
                  <th>Size</th>
                  <th>Cryptographic SHA-256 Hash</th>
                  <th>Integrity Status</th>
                  <th>Last Verified</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {vaultItems.map((item) => {
                  const isVerified = item.integrity_status === 'VERIFIED';
                  const isVerifying = verifyingId === item.evidence_id;
                  return (
                    <tr key={item.evidence_id}>
                      <td className="mono cell-id">{item.evidence_id}</td>
                      <td><span className="mono badge badge-neutral">{item.case_id}</span></td>
                      <td className="text-primary">{item.source_title}</td>
                      <td className="mono cell-small text-muted">{item.original_source_path}</td>
                      <td className="mono">{item.record_count} lines</td>
                      <td className="mono">{item.file_size_bytes} B</td>
                      <td className="mono cell-small truncate" style={{ maxWidth: '180px' }} title={item.sha256_hash}>
                        {item.sha256_hash}
                      </td>
                      <td>
                        <span className={`badge ${isVerified ? 'badge-teal' : 'badge-red'}`}>
                          {isVerified ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
                          {item.integrity_status}
                        </span>
                      </td>
                      <td className="mono cell-small">{new Date(item.last_verified_at).toLocaleTimeString()}</td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          disabled={isVerifying}
                          onClick={() => handleVerify(item.evidence_id)}
                        >
                          <ShieldCheck size={12} />
                          {isVerifying ? 'Verifying...' : 'Verify Integrity'}
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
            No forensic evidence preserved in the vault yet.
            {activeCase
              ? ' Click "Preserve Prioritized Evidence for Active Case" above to preserve the evidence prioritization selects, with SHA-256 hashing.'
              : ' Evidence can be preserved once an investigation case is open.'}
          </div>
        )}
      </div>

      {/* Verification Result Modal */}
      {verificationResult && (
        <div className="modal-backdrop" onClick={() => setVerificationResult(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">
                <ShieldCheck size={18} className={verificationResult.verified ? 'text-teal' : 'text-red'} />
                Integrity Verification: {verificationResult.evidence_id}
              </span>
              <button className="btn btn-secondary" onClick={() => setVerificationResult(null)}>Close</button>
            </div>

            <div className="modal-body">
              <div>
                <b>Verification Status: </b>
                <span className={`badge ${verificationResult.verified ? 'badge-teal' : 'badge-red'}`} style={{ marginLeft: '6px' }}>
                  {verificationResult.status}
                </span>
              </div>

              <div>
                <b>Expected SHA-256 Hash (Custody Record):</b>
                <pre className="code-block">{verificationResult.expected_sha256}</pre>
              </div>

              <div>
                <b>Calculated SHA-256 Hash (Current Disk File):</b>
                <pre className={`code-block ${verificationResult.verified ? 'text-teal' : 'text-red'}`}>
                  {verificationResult.calculated_sha256}
                </pre>
              </div>

              <div
                className={`panel ${verificationResult.verified ? 'panel-accent' : 'panel-accent-red'}`}
                style={{ marginTop: '6px' }}
              >
                <div className="text-primary" style={{ fontWeight: 500 }}>{verificationResult.explanation}</div>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
