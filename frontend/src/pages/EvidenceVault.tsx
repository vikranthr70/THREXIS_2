import React, { useState } from 'react';
import { Vault, ShieldCheck } from 'lucide-react';
import type { EvidenceVaultItem, InvestigationCase, AcquireSelectionResult } from '../types';
import { api } from '../services/api';
import { AcquisitionSummary } from '../components/AcquisitionSummary';
import { Chip, StatusDot } from '../components/ui';
import type { PrioritizationContext } from '../utils/threatContext';
import { parseServerTime } from '../utils/time';
import { fmtBytes, labelize } from '../utils/format';

interface EvidenceVaultProps {
  vaultItems: EvidenceVaultItem[];
  activeCase: InvestigationCase | null;
  /** Same context and budget as the Evidence Prioritization page. */
  prioritizationContext: PrioritizationContext;
  budget: number;
  onRefresh: () => void;
}

/** Verified hashes are the one place emerald is used; tampering is the alert case. */
const IntegrityStatus: React.FC<{ status: string }> = ({ status }) => {
  if (status === 'VERIFIED') return <StatusDot tone="ok">Verified</StatusDot>;
  if (status === 'TAMPERED') return <Chip tone="crit">Tampered</Chip>;
  if (status === 'FILE_MISSING') return <Chip tone="crit">File missing</Chip>;
  return <StatusDot tone="muted">{labelize(status)}</StatusDot>;
};

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
  // current budget. The server only creates vault items for sources backed by real
  // collector telemetry; the rest are reported as needing host-side acquisition.
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

  const verifiedCount = vaultItems.filter((v) => v.integrity_status === 'VERIFIED').length;
  const failedCount = vaultItems.filter((v) => v.integrity_status === 'TAMPERED' || v.integrity_status === 'FILE_MISSING').length;

  return (
    <div className="page-container page-stack">

      {/* Acquire */}
      <div className="card">
        <div className="card-body row-between wrap">
          <div className="stack" style={{ gap: 2 }}>
            <span className="card-title">Preserve evidence</span>
            <span className="text-sm text-secondary">
              Copies are hashed with SHA-256 at acquisition and recorded in a custody manifest.
            </span>
          </div>
          {activeCase ? (
            <div className="row-lg">
              <span className="text-sm text-secondary">
                Adaptive · budget {budget} · {prioritizationContext.value} {prioritizationContext.auto ? '(auto)' : '(manual)'}
              </span>
              <button className="btn btn-primary" onClick={handlePreserveForCase} disabled={acquiring}>
                <Vault size={13} />
                {acquiring ? 'Preserving…' : `Preserve for ${activeCase.case_id}`}
              </button>
            </div>
          ) : (
            <span className="text-sm text-muted">Available when an investigation case is open.</span>
          )}
        </div>
        {acquisition && <AcquisitionSummary result={acquisition} onDismiss={() => setAcquisition(null)} />}
      </div>

      {/* Inventory */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Evidence inventory</span>
          <span className="card-meta">
            {vaultItems.length} item{vaultItems.length === 1 ? '' : 's'} · {verifiedCount} verified
            {failedCount > 0 && <span className="text-crit"> · {failedCount} failed</span>}
          </span>
        </div>

        {vaultItems.length > 0 ? (
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Evidence</th>
                  <th>Case</th>
                  <th>Source</th>
                  <th>Original path</th>
                  <th>SHA-256</th>
                  <th>Integrity</th>
                  <th className="num">Records</th>
                  <th className="num">Size</th>
                  <th className="num">Last verified</th>
                  <th className="actions"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {vaultItems.map((item) => {
                  const isVerifying = verifyingId === item.evidence_id;
                  return (
                    <tr key={item.evidence_id}>
                      <td className="cell-primary">{item.evidence_id}</td>
                      <td className="cell-secondary">{item.case_id}</td>
                      <td>{item.source_title}</td>
                      <td className="mono cell-secondary">{item.original_source_path}</td>
                      <td className="mono cell-secondary truncate" style={{ maxWidth: 160 }} title={item.sha256_hash}>
                        {item.sha256_hash}
                      </td>
                      <td><IntegrityStatus status={item.integrity_status} /></td>
                      <td className="num">{item.record_count}</td>
                      <td className="num">{fmtBytes(item.file_size_bytes)}</td>
                      <td className="num mono cell-secondary">{parseServerTime(item.last_verified_at).toLocaleTimeString()}</td>
                      <td className="actions">
                        <button
                          className="btn btn-secondary btn-sm"
                          disabled={isVerifying}
                          onClick={() => handleVerify(item.evidence_id)}
                        >
                          <ShieldCheck size={12} />
                          {isVerifying ? 'Verifying…' : 'Verify'}
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
            <div className="empty-state-title">No evidence preserved yet</div>
            <div className="empty-state-hint">
              {activeCase ? 'Use Preserve above to acquire the prioritized evidence for the open case.' : 'Evidence can be preserved once a case is open.'}
            </div>
          </div>
        )}
      </div>

      {verificationResult && (
        <div className="modal-backdrop" onClick={() => setVerificationResult(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">Integrity check · {verificationResult.evidence_id}</span>
              <button className="btn btn-ghost btn-sm" onClick={() => setVerificationResult(null)}>Close</button>
            </div>
            <div className="modal-body">
              <div className="row">
                <IntegrityStatus status={verificationResult.status} />
                <span className="text-secondary">{verificationResult.explanation}</span>
              </div>
              <div>
                <div className="section-label">Expected (custody record)</div>
                <pre className="code-block">{verificationResult.expected_sha256}</pre>
              </div>
              <div>
                <div className="section-label">Calculated (file on disk)</div>
                <pre className={`code-block ${verificationResult.verified ? '' : 'text-crit'}`}>{verificationResult.calculated_sha256}</pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
