import React, { useState, useEffect } from 'react';
import { Vault, RotateCcw, ArrowRight } from 'lucide-react';
import type {
  PrioritizationResult,
  StrategyComparisonItem,
  InvestigationCase,
  AcquireSelectionResult
} from '../types';
import { api } from '../services/api';
import { AcquisitionSummary } from '../components/AcquisitionSummary';
import { StatusDot } from '../components/ui';
import { PRIORITIZATION_CONTEXTS, type PrioritizationContext } from '../utils/threatContext';

interface EvidencePrioritizationProps {
  /** Context in use: follows the detected technique unless manually overridden. */
  context: PrioritizationContext;
  onOverrideContext: (contextId: string | null) => void;
  budget: number;
  onBudgetChange: (budget: number) => void;
  activeCase: InvestigationCase | null;
  onRefresh: () => void;
  onNavigateToVault: () => void;
}

const STRATEGIES: { id: string; label: string; description: string; behaviour: string }[] = [
  { id: 'adaptive', label: 'Adaptive (threat-informed)', description: 'Ranks by ATT&CK affinity × weight × availability ÷ cost.', behaviour: 'Selects the evidence most relevant to the detected technique first.' },
  { id: 'static', label: 'Static order', description: 'Fixed priority order, ignores detections.', behaviour: 'Misses high-value evidence when the attack differs from the default order.' },
  { id: 'random', label: 'Random', description: 'Random order within the budget.', behaviour: 'High variance; unpredictable gaps.' },
  { id: 'threat_agnostic', label: 'Threat-agnostic', description: 'Ranks by availability ÷ cost only.', behaviour: 'Favours cheap sources regardless of relevance.' },
  { id: 'frozen_context', label: 'Frozen context', description: 'Uses the baseline model and never adapts.', behaviour: 'Does not follow a change in attacker behaviour.' }
];
const strategyLabel = (id: string) => STRATEGIES.find((s) => s.id === id)?.label ?? id;

const recallClass = (r: number) => (r < 0.5 ? 'text-crit' : r < 0.8 ? 'text-warn' : 'text-heading');

export const EvidencePrioritization: React.FC<EvidencePrioritizationProps> = ({
  context,
  onOverrideContext,
  budget,
  onBudgetChange,
  activeCase,
  onRefresh,
  onNavigateToVault
}) => {
  const threatContext = context.value;
  const [strategy, setStrategy] = useState<string>('adaptive');
  const [result, setResult] = useState<PrioritizationResult | null>(null);
  const [comparison, setComparison] = useState<StrategyComparisonItem[]>([]);
  const [preserving, setPreserving] = useState<boolean>(false);
  const [acquisition, setAcquisition] = useState<AcquireSelectionResult | null>(null);

  const handlePreserveSelection = async () => {
    if (!activeCase || !result) return;
    setPreserving(true);
    try {
      const res = await api.acquireSelection(activeCase.case_id, {
        sourceKeys: result.selected_sources.map((s) => s.source_key)
      });
      setAcquisition(res);
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setPreserving(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.runPrioritization(strategy, budget, threatContext);
        const compData = await api.compareStrategies(budget, threatContext);
        if (cancelled) return;
        setResult(data);
        setComparison(compData.strategies_comparison);
      } catch (err) {
        console.error(err);
      }
    })();
    return () => { cancelled = true; };
  }, [strategy, budget, threatContext]);

  const current = STRATEGIES.find((s) => s.id === strategy);

  return (
    <div className="page-container page-stack">

      {/* Parameters */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Parameters</span>
          <span className="card-meta">{current?.description}</span>
        </div>
        <div className="card-body grid-3" style={{ gap: 20 }}>
          <div>
            <label className="field-label" htmlFor="prio-strategy">Strategy</label>
            <select id="prio-strategy" className="form-control" value={strategy} onChange={(e) => setStrategy(e.target.value)}>
              {STRATEGIES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </div>

          <div>
            <div className="row-between">
              <label className="field-label" htmlFor="prio-budget">Collection budget</label>
              <span className="text-sm text-heading num">{budget} units</span>
            </div>
            <input
              id="prio-budget" type="range" min="15" max="120" step="5" value={budget}
              onChange={(e) => onBudgetChange(parseFloat(e.target.value))}
              className="form-range"
            />
            <div className="range-scale"><span>15</span><span>60</span><span>120</span></div>
          </div>

          <div>
            <label className="field-label" htmlFor="prio-context">Threat context</label>
            <select id="prio-context" className="form-control" value={threatContext} onChange={(e) => onOverrideContext(e.target.value)}>
              {PRIORITIZATION_CONTEXTS.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
            </select>
            <div className="row wrap" style={{ marginTop: 6 }}>
              <StatusDot tone={context.auto ? 'ok' : 'warn'}>{context.auto ? 'Auto' : 'Manual'}</StatusDot>
              <span className="text-xs text-muted">{context.note}</span>
              {!context.auto && (
                <button className="btn btn-ghost btn-sm" onClick={() => onOverrideContext(null)}>
                  <RotateCcw size={11} /> Follow detections
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {result && (
        <div className="grid-4">
          <div className="card kpi">
            <div className="kpi-label">Budget used</div>
            <div className="kpi-value">{result.budget_used.toFixed(0)} <span className="text-secondary" style={{ fontSize: 16 }}>/ {result.budget_limit.toFixed(0)}</span></div>
            <div className="kpi-sub">{result.budget_utilization_pct}% utilized · {result.remaining_budget.toFixed(0)} remaining</div>
          </div>
          <div className="card kpi">
            <div className="kpi-label">Critical evidence recall</div>
            <div className={`kpi-value ${recallClass(result.metrics.recall)}`}>{(result.metrics.recall * 100).toFixed(0)}%</div>
            <div className="kpi-sub">{result.metrics.true_positives} of {result.metrics.total_relevant} critical sources selected</div>
          </div>
          <div className="card kpi">
            <div className="kpi-label">Precision</div>
            <div className="kpi-value">{(result.metrics.precision * 100).toFixed(0)}%</div>
            <div className="kpi-sub">Selected sources that are critical</div>
          </div>
          <div className="card kpi">
            <div className="kpi-label">Cost per critical source</div>
            <div className="kpi-value">{result.metrics.cost_per_relevant_item.toFixed(1)}</div>
            <div className="kpi-sub">Budget units</div>
          </div>
        </div>
      )}

      {result && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Ranked evidence</span>
            <div className="row">
              <span className="card-meta">{result.selected_sources.length} selected · greedy knapsack</span>
              {activeCase && (
                <button
                  className="btn btn-primary btn-sm"
                  onClick={handlePreserveSelection}
                  disabled={preserving || result.selected_sources.length === 0}
                  title={`Preserve the selected sources for ${activeCase.case_id}`}
                >
                  <Vault size={12} />
                  {preserving ? 'Preserving…' : `Preserve ${result.selected_sources.length} selected`}
                </button>
              )}
            </div>
          </div>

          {acquisition && (
            <AcquisitionSummary
              result={acquisition}
              onDismiss={() => setAcquisition(null)}
              action={<button className="btn btn-ghost btn-sm" onClick={onNavigateToVault}>Open Vault <ArrowRight size={12} /></button>}
            />
          )}

          <div className="data-table-container" style={acquisition ? { borderTop: '1px solid var(--border)' } : undefined}>
            <table className="data-table">
              <thead>
                <tr>
                  <th className="num">#</th>
                  <th>Source</th>
                  <th>Category</th>
                  <th>Decision</th>
                  <th>Rationale</th>
                  <th className="num">Priority</th>
                  <th className="num">Affinity</th>
                  <th className="num">Availability</th>
                  <th className="num">Cost</th>
                  <th className="num">Budget left</th>
                </tr>
              </thead>
              <tbody>
                {result.ranked_items.map((item, idx) => (
                  <tr key={item.source_key} className={item.selected ? '' : 'row-dimmed'}>
                    <td className="num cell-secondary">{idx + 1}</td>
                    <td className="cell-primary">{item.source_name}</td>
                    <td className="cell-secondary">{item.category}</td>
                    <td>
                      {item.selected
                        ? <StatusDot tone="ok">Selected</StatusDot>
                        : <StatusDot tone="muted" title={item.rejection_reason}>Excluded</StatusDot>}
                    </td>
                    <td className="cell-secondary truncate" style={{ maxWidth: 300 }} title={item.rationale}>{item.rationale}</td>
                    <td className="num text-heading">{item.priority_score.toFixed(3)}</td>
                    <td className="num">{item.threat_affinity !== undefined ? item.threat_affinity.toFixed(2) : '—'}</td>
                    <td className="num">{item.availability_factor.toFixed(2)}</td>
                    <td className="num">{item.cost.toFixed(0)}</td>
                    <td className="num cell-secondary">{item.remaining_after !== undefined ? item.remaining_after : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <span className="card-title">Strategy comparison</span>
          <span className="card-meta">Same budget ({budget}) and context ({threatContext})</span>
        </div>
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Strategy</th>
                <th>Behaviour</th>
                <th className="num">Sources</th>
                <th className="num">Budget used</th>
                <th className="num">Utilization</th>
                <th className="num">Recall</th>
                <th className="num">Precision</th>
                <th className="num">Cost / critical</th>
              </tr>
            </thead>
            <tbody>
              {comparison.map((comp) => {
                const isSelected = comp.strategy === strategy;
                return (
                  <tr key={comp.strategy} className={isSelected ? 'row-selected' : ''}>
                    <td className="cell-primary">
                      {strategyLabel(comp.strategy)}
                      {isSelected && <span className="text-xs text-muted"> · current</span>}
                    </td>
                    <td className="cell-secondary truncate" style={{ maxWidth: 320 }}>
                      {STRATEGIES.find((s) => s.id === comp.strategy)?.behaviour}
                    </td>
                    <td className="num">{comp.selected_count}</td>
                    <td className="num">{comp.budget_used.toFixed(0)}</td>
                    <td className="num">{comp.utilization_pct.toFixed(1)}%</td>
                    <td className={`num ${recallClass(comp.recall)}`}>{(comp.recall * 100).toFixed(0)}%</td>
                    <td className="num">{(comp.precision * 100).toFixed(0)}%</td>
                    <td className="num">{comp.cost_per_relevant.toFixed(1)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
