import React, { useState, useEffect } from 'react';
import { ListOrdered, Sliders, CheckCircle2, XCircle, BarChart2 } from 'lucide-react';
import type { PrioritizationResult, StrategyComparisonItem } from '../types';
import { api } from '../services/api';

export const EvidencePrioritization: React.FC = () => {
  const [strategy, setStrategy] = useState<string>('adaptive');
  const [budget, setBudget] = useState<number>(60);
  const [threatContext, setThreatContext] = useState<string>('T1110');
  const [result, setResult] = useState<PrioritizationResult | null>(null);
  const [comparison, setComparison] = useState<StrategyComparisonItem[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  const runPrioritization = async () => {
    setLoading(true);
    try {
      const data = await api.runPrioritization(strategy, budget, threatContext);
      setResult(data);
      const compData = await api.compareStrategies(budget, threatContext);
      setComparison(compData.strategies_comparison);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runPrioritization();
  }, [strategy, budget, threatContext]);

  const STRATEGY_DESCRIPTIONS: Record<string, string> = {
    'adaptive': 'Dynamic utility ranking based on observed MITRE ATT&CK technique affinity, availability factor, and acquisition cost.',
    'static': 'Fixed baseline priority order regardless of observed security events or active threats.',
    'random': 'Stochastic baseline evidence selection within collection budget limit.',
    'threat_agnostic': 'Ranks evidence solely by availability-to-cost ratio, completely ignoring active attack behavior.',
    'frozen_context': 'Uses initial baseline threat model but refuses to adapt when telemetry indicates threat context shifts.'
  };

  return (
    <div className="page-container page-stack">
      
      {/* Top Controls Card: Budget & Strategy Configuration */}
      <div className="card card-accent">
        <div className="card-header">
          <span className="card-title">
            <Sliders size={16} className="text-teal" />
            Adaptive Prioritization Parameters & Threat Context
          </span>
          <span className="badge badge-teal">Core Research Optimization</span>
        </div>

        <div className="grid-3" style={{ marginBottom: '14px' }}>
          {/* Strategy selector */}
          <div>
            <label className="label" htmlFor="prio-strategy" style={{ marginBottom: '6px' }}>
              Selection Strategy
            </label>
            <select
              id="prio-strategy"
              className="form-control"
              value={strategy}
              onChange={(e) => setStrategy(e.target.value)}
            >
              <option value="adaptive">1. Adaptive Threat-Informed (Recommended)</option>
              <option value="static">2. Static Selection (Fixed Baseline)</option>
              <option value="random">3. Random Selection (Stochastic Baseline)</option>
              <option value="threat_agnostic">4. Threat-Agnostic (Cost-Availability Only)</option>
              <option value="frozen_context">5. Frozen-Context (Stale Model)</option>
            </select>
          </div>

          {/* Budget Limit Slider */}
          <div>
            <div className="row-between" style={{ marginBottom: '6px' }}>
              <label className="label" htmlFor="prio-budget">
                Collection Budget Constraint
              </label>
              <span className="mono text-teal" style={{ fontWeight: 600 }}>
                {budget.toFixed(1)} Units
              </span>
            </div>
            <input
              id="prio-budget"
              type="range"
              min="15"
              max="120"
              step="5"
              value={budget}
              onChange={(e) => setBudget(parseFloat(e.target.value))}
              className="form-range"
            />
            <div className="meter-scale" style={{ marginTop: '2px' }}>
              <span>15 (Constrained)</span>
              <span>60 (Moderate)</span>
              <span>120 (Permissive)</span>
            </div>
          </div>

          {/* Threat Context */}
          <div>
            <label className="label" htmlFor="prio-context" style={{ marginBottom: '6px' }}>
              Observed Threat Context
            </label>
            <select
              id="prio-context"
              className="form-control"
              value={threatContext}
              onChange={(e) => setThreatContext(e.target.value)}
            >
              <option value="T1110">T1110: SSH Brute Force / Password Guessing</option>
              <option value="T1548.003">T1548.003: Privilege Escalation / Sudo Abuse</option>
              <option value="T1059.004">T1059.004: Unix Shell & Scripting Execution</option>
              <option value="BASELINE">BASELINE: Normal Security Operations</option>
            </select>
          </div>
        </div>

        <div className="panel-inset text-md text-secondary" style={{ padding: 'var(--space-2) var(--space-3)' }}>
          <b className="text-teal">Strategy Logic: </b>
          {STRATEGY_DESCRIPTIONS[strategy]}
        </div>
      </div>

      {/* KPI Cards: Budget Utilization, Recall, Precision */}
      {result && (
        <div className="grid-4">
          <div className="card stat-card">
            <div className="label">Budget Allocated / Used</div>
            <div className="stat-value">{result.budget_used.toFixed(1)} / {result.budget_limit.toFixed(1)}</div>
            <div className="stat-sub text-teal">
              {result.budget_utilization_pct}% utilization ({result.remaining_budget.toFixed(1)} rem)
            </div>
          </div>

          <div className="card stat-card">
            <div className="label">Relevant Evidence Recall</div>
            <div className={`stat-value ${result.metrics.recall >= 0.8 ? 'text-teal' : 'text-amber'}`}>
              {(result.metrics.recall * 100).toFixed(0)}%
            </div>
            <div className="stat-sub">
              {result.metrics.true_positives} of {result.metrics.total_relevant} critical sources captured
            </div>
          </div>

          <div className="card stat-card">
            <div className="label">Selection Precision</div>
            <div className="stat-value">{(result.metrics.precision * 100).toFixed(0)}%</div>
            <div className="stat-sub">Fraction of acquired items matching threat</div>
          </div>

          <div className="card stat-card">
            <div className="label">Cost per Relevant Source</div>
            <div className="stat-value">{result.metrics.cost_per_relevant_item.toFixed(1)} units</div>
            <div className="stat-sub">Acquisition resource efficiency</div>
          </div>
        </div>
      )}

      {/* Ranked Candidate Sources Table */}
      {result && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <ListOrdered size={16} className="text-teal" />
              Ranked Evidence Candidate Items ({result.selected_sources.length} Selected within Budget)
            </span>
            <span className="badge badge-neutral">Knapsack Budget Constraint</span>
          </div>

          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rank</th>
                  <th>Evidence Source</th>
                  <th>Category</th>
                  <th>Priority Score</th>
                  <th>Threat Affinity</th>
                  <th>Acquisition Cost</th>
                  <th>Availability Factor</th>
                  <th>Status Decision</th>
                  <th>Remaining Budget</th>
                  <th>Selection Rationale</th>
                </tr>
              </thead>
              <tbody>
                {result.ranked_items.map((item, idx) => (
                  <tr key={item.source_key} className={item.selected ? '' : 'row-dimmed'}>
                    <td className={`mono ${item.selected ? 'text-teal' : 'text-muted'}`} style={{ fontWeight: 600 }}>
                      #{idx + 1}
                    </td>
                    <td className={item.selected ? 'cell-strong' : ''} style={{ fontWeight: 600 }}>
                      {item.source_name}
                    </td>
                    <td><span className="badge badge-neutral">{item.category}</span></td>
                    <td className={`mono ${item.selected ? 'text-teal' : 'text-primary'}`} style={{ fontWeight: 700 }}>
                      {item.priority_score.toFixed(3)}
                    </td>
                    <td className="mono">
                      {item.threat_affinity !== undefined ? item.threat_affinity.toFixed(2) : 'N/A'}
                    </td>
                    <td className="mono">{item.cost.toFixed(1)} u</td>
                    <td className="mono">{item.availability_factor.toFixed(2)}</td>
                    <td>
                      {item.selected ? (
                        <span className="badge badge-teal">
                          <CheckCircle2 size={11} /> SELECTED
                        </span>
                      ) : (
                        <span className="badge badge-red" title={item.rejection_reason}>
                          <XCircle size={11} /> EXCLUDED
                        </span>
                      )}
                    </td>
                    <td className="mono text-muted">
                      {item.remaining_after !== undefined ? `${item.remaining_after} u` : 'N/A'}
                    </td>
                    <td className="cell-note">
                      {item.rationale}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 5-Strategy Comparative Benchmark Matrix */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <BarChart2 size={16} className="text-teal" />
            Comparative Benchmark: All 5 Prioritization Strategies (Budget = {budget.toFixed(0)} Units)
          </span>
          <span className="badge badge-teal">Academic Baseline Comparison</span>
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Strategy</th>
                <th>Sources Acquired</th>
                <th>Budget Used</th>
                <th>Utilization</th>
                <th>Relevant Recall</th>
                <th>Precision</th>
                <th>Cost / Relevant Source</th>
                <th>Academic Behavior</th>
              </tr>
            </thead>
            <tbody>
              {comparison.map((comp) => {
                const isSelected = comp.strategy === strategy;
                return (
                  <tr key={comp.strategy} className={isSelected ? 'row-selected' : ''}>
                    <td className={isSelected ? 'text-teal' : 'text-primary'} style={{ fontWeight: 600 }}>
                      {comp.strategy.toUpperCase().replace('_', ' ')}
                      {isSelected && <span className="badge badge-teal badge-xs" style={{ marginLeft: '6px' }}>ACTIVE</span>}
                    </td>
                    <td className="mono">{comp.selected_count} sources</td>
                    <td className="mono">{comp.budget_used.toFixed(1)} u</td>
                    <td className="mono">{comp.utilization_pct.toFixed(1)}%</td>
                    <td className="mono" style={{ fontWeight: 700, color: comp.recall >= 0.8 ? 'var(--teal-glow)' : (comp.recall >= 0.5 ? 'var(--amber-bright)' : 'var(--red-oxide-bright)') }}>
                      {(comp.recall * 100).toFixed(0)}%
                    </td>
                    <td className="mono">{(comp.precision * 100).toFixed(0)}%</td>
                    <td className="mono">{comp.cost_per_relevant.toFixed(1)} u</td>
                    <td className="cell-note">
                      {comp.strategy === 'adaptive' && 'Optimal: Adapts to threat telemetry to select critical sources first.'}
                      {comp.strategy === 'static' && 'Fixed baseline: Misses high-value evidence when attacks diverge from default order.'}
                      {comp.strategy === 'random' && 'Stochastic: Exhibits high variance and unpredictable evidence gaps.'}
                      {comp.strategy === 'threat_agnostic' && 'Cost-biased: Collects cheap irrelevant logs while missing critical authentication telemetry.'}
                      {comp.strategy === 'frozen_context' && 'Stale context: Fails to detect pivots due to outdated threat priors.'}
                    </td>
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
