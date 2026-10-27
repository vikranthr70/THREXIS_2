import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { CommandCenter } from './pages/CommandCenter';
import { ForensicReadiness } from './pages/ForensicReadiness';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { EvidencePrioritization } from './pages/EvidencePrioritization';
import { IncidentInvestigation } from './pages/IncidentInvestigation';
import { EvidenceVault } from './pages/EvidenceVault';
import { api } from './services/api';
import { deriveActiveThreat, isOpenStatus, resolvePrioritizationContext } from './utils/threatContext';
import type {
  ReadinessAssessment,
  SecurityEvent,
  DetectionAlert,
  MitreTechnique,
  EvidenceVaultItem,
  CollectorStatus,
  InvestigationCase
} from './types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('command-center');
  const [readiness, setReadiness] = useState<ReadinessAssessment | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<DetectionAlert[]>([]);
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [vaultItems, setVaultItems] = useState<EvidenceVaultItem[]>([]);
  const [collectorStatus, setCollectorStatus] = useState<CollectorStatus | null>(null);
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [apiReachable, setApiReachable] = useState<boolean | null>(null);

  // The active case is the most recently updated case that is still open; a closed
  // case must not keep driving the dashboard's threat context.
  const activeCase = useMemo(() => cases.find((c) => isOpenStatus(c.status)) ?? null, [cases]);
  const activeThreat = useMemo(() => deriveActiveThreat(alerts, activeCase), [alerts, activeCase]);

  // Prioritization settings live here so the Prioritization page and the Vault use
  // the same budget and threat context. The context follows the detected technique
  // unless the analyst overrides it.
  const [collectionBudget, setCollectionBudget] = useState<number>(60);
  const [contextOverride, setContextOverride] = useState<string | null>(null);
  const prioritizationContext = useMemo(
    () => resolvePrioritizationContext(activeThreat, contextOverride),
    [activeThreat, contextOverride]
  );

  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [eData, aData, tData, vData, cStatus, caseList] = await Promise.all([
        api.getRecentEvents(60).catch(() => []),
        api.getAlerts().catch(() => []),
        api.getMitreTechniques().catch(() => []),
        api.getVaultItems().catch(() => []),
        api.getCollectorStatus().catch(() => null),
        api.getCases().catch(() => [])
      ]);

      // Readiness is scored against the technique of the current alert/case so the
      // backend can apply its threat-specific weight profile (e.g. T1110). It is
      // fetched after alerts/cases so the context always matches this refresh.
      const threat = deriveActiveThreat(aData, caseList.find((c) => isOpenStatus(c.status)) ?? null);
      const rData = await api.getReadiness(threat?.techniqueId).catch(() => null);

      setApiReachable(rData !== null);
      if (rData) setReadiness(rData);
      setEvents(eData);
      setAlerts(aData);
      setTechniques(tData);
      setVaultItems(vData);
      setCollectorStatus(cStatus);
      setCases(caseList);
    } catch (err) {
      console.error('Error fetching dashboard state:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadData();
    // Continuous background sync every 3 seconds for real-time live detection
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, [loadData]);

  // WebSocket Live Connection for instantaneous real-time event alerts
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    let ws: WebSocket;

    try {
      ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (
            msg.type === 'TELEMETRY_BATCH' ||
            msg.type === 'NEW_ALERTS' ||
            msg.type === 'READINESS_UPDATED' ||
            msg.type === 'COLLECTOR_HEARTBEAT' ||
            msg.type === 'EVIDENCE_PRESERVED'
          ) {
            loadData();
          }
        } catch (e) {
          // ignore heartbeat ping
        }
      };

      ws.onerror = (err) => {
        console.warn('WebSocket connection notice:', err);
      };
    } catch (e) {
      console.warn('WebSocket init exception:', e);
    }

    return () => {
      if (ws) ws.close();
    };
  }, [loadData]);

  return (
    <div className="app-container">
      <Sidebar currentTab={currentTab} setCurrentTab={setCurrentTab} activeCase={activeCase} />

      <div className="main-content">
        <Header
          currentTab={currentTab}
          onRefresh={loadData}
          isRefreshing={isRefreshing}
          apiReachable={apiReachable}
          collectorStatus={collectorStatus}
          activeCase={activeCase}
          totalEventsCount={events.length}
          lastEventTime={events.length > 0 ? events[0].timestamp : null}
          onOpenCase={() => setCurrentTab('investigation')}
        />

        {currentTab === 'command-center' && (
          <CommandCenter
            readiness={readiness}
            events={events}
            alerts={alerts}
            techniques={techniques}
            activeThreat={activeThreat}
            activeCase={activeCase}
            onNavigate={setCurrentTab}
          />
        )}

        {currentTab === 'readiness' && (
          <ForensicReadiness
            readiness={readiness}
            onRefresh={loadData}
          />
        )}

        {currentTab === 'detection' && (
          <ThreatIntelligence
            alerts={alerts}
            techniques={techniques}
            onNavigateToInvestigation={() => setCurrentTab('investigation')}
          />
        )}

        {currentTab === 'prioritization' && (
          <EvidencePrioritization
            context={prioritizationContext}
            onOverrideContext={setContextOverride}
            budget={collectionBudget}
            onBudgetChange={setCollectionBudget}
            activeCase={activeCase}
            onRefresh={loadData}
            onNavigateToVault={() => setCurrentTab('vault')}
          />
        )}

        {currentTab === 'investigation' && (
          <IncidentInvestigation
            cases={cases}
            activeCase={activeCase}
            vaultItems={vaultItems}
            onRefresh={loadData}
            onNavigateToVault={() => setCurrentTab('vault')}
          />
        )}

        {currentTab === 'vault' && (
          <EvidenceVault
            vaultItems={vaultItems}
            activeCase={activeCase}
            prioritizationContext={prioritizationContext}
            budget={collectionBudget}
            onRefresh={loadData}
          />
        )}
      </div>
    </div>
  );
};

export default App;
