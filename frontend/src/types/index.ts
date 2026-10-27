export interface SecurityEvent {
  id: number;
  event_id: string;
  host: string;
  timestamp: string;
  source: string;
  event_type: string;
  user: string | null;
  source_ip: string | null;
  source_port: number | null;
  pid: number | null;
  message: string;
  raw_log: string;
  sha256: string;
  ingested_at: string;
}

export interface DetectionAlert {
  id: number;
  alert_id: string;
  rule_id: string;
  rule_name: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  technique_id: string;
  technique_name: string;
  tactic: string;
  explanation: string;
  rationale: string;
  event_count: number;
  first_event_at: string;
  last_event_at: string;
  source_host: string;
  source_ip: string | null;
  target_user: string | null;
  supporting_event_ids: string[];
  status: string;
  created_at: string;
}

export interface EvidenceSource {
  source_key: string;
  source_name: string;
  category: string;
  status: 'unknown' | 'missing' | 'unavailable' | 'available' | 'collected' | 'validated' | 'not_applicable';
  weight: number;
  factor: number;
  weighted_score: number;
  collection_cost: number;
  details: string;
  last_activity_at: string | null;
}

export interface ReadinessGap {
  source_key: string;
  source_name: string;
  category: string;
  status: string;
  weight: number;
  current_factor: number;
  penalty: number;
  remediation: string;
}

export interface RemediationRecommendation {
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  source: string;
  action: string;
  impact: string;
}

export interface ReadinessAssessment {
  score: number;
  category: string;
  weighted_sum: number;
  total_weight: number;
  coverage_percentage: number;
  source_count: number;
  gaps_count: number;
  formula: string;
  sources: EvidenceSource[];
  gaps: ReadinessGap[];
  recommendations: RemediationRecommendation[];
  timestamp: string;
  threat_context: string;
  /** Weight adjustment applied for the active technique; null/absent = baseline weights. */
  weight_profile?: WeightProfile | null;
}

export interface WeightProfile {
  technique: string;
  boosted_sources: string[];
  multiplier: number;
  affinity_threshold: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  description: string;
  subtechniques?: { id: string; name: string; description: string }[];
  detection_methods: string;
  evidence_sources: string[];
  url: string;
  applicable_platforms?: string[];
}

export interface RankedSourceItem {
  source_key: string;
  source_name: string;
  category: string;
  status: string;
  base_weight: number;
  cost: number;
  availability_factor: number;
  priority_score: number;
  threat_affinity?: number;
  rationale: string;
  selected: boolean;
  remaining_after?: number;
  rejection_reason?: string;
}

export interface PrioritizationResult {
  run_id: string;
  timestamp: string;
  strategy: string;
  budget_limit: number;
  budget_used: number;
  remaining_budget: number;
  budget_utilization_pct: number;
  threat_context: string;
  ranked_items: RankedSourceItem[];
  selected_sources: RankedSourceItem[];
  unselected_sources: RankedSourceItem[];
  metrics: {
    recall: number;
    precision: number;
    cost_per_relevant_item: number;
    true_positives: number;
    total_relevant: number;
  };
}

export interface StrategyComparisonItem {
  strategy: string;
  budget_used: number;
  remaining_budget: number;
  utilization_pct: number;
  selected_count: number;
  selected_sources: string[];
  recall: number;
  precision: number;
  cost_per_relevant: number;
}

export interface InvestigationCase {
  id: number;
  case_id: string;
  title: string;
  status: string;
  severity: string;
  created_at: string;
  updated_at: string;
  primary_technique: string;
  summary: string;
  scope_and_methodology: string;
  analyst_notes: string;
  findings: string[];
  unresolved_questions: string[];
  readiness_score_at_time: number;
  supporting_event_ids: string[];
  supporting_alert_ids: string[];
}

export interface TimelineItem {
  id: string;
  timestamp: string;
  type: 'SECURITY_EVENT' | 'DETECTION_ALERT' | 'EVIDENCE_ACQUIRED';
  title: string;
  description: string;
  host?: string;
  source?: string;
  user?: string;
  source_ip?: string;
  sha256?: string;
  severity?: string;
  technique?: string;
}

export interface EvidenceVaultItem {
  id: number;
  evidence_id: string;
  case_id: string;
  source_key: string;
  source_title: string;
  original_source_path: string;
  description: string;
  record_count: number;
  file_size_bytes: number;
  acquired_at: string;
  sha256_hash: string;
  integrity_status: 'VERIFIED' | 'TAMPERED' | 'UNVERIFIED' | 'FILE_MISSING';
  last_verified_at: string;
  storage_path: string;
  manifest: any;
}

export interface CollectorStatus {
  connected_collectors_count: number;
  collectors: {
    host_id: string;
    hostname: string;
    ip_address: string;
    collector_version: string;
    os_info: string;
    status: 'ONLINE' | 'OFFLINE';
    events_transmitted: number;
    last_heartbeat_at: string;
    seconds_since_last_seen: number;
  }[];
}

export interface AcquireSelectionResult {
  case_id: string;
  selection: {
    origin: 'client_selection' | 'server_adaptive';
    run_id: string | null;
    budget: number | null;
    threat_context: string | null;
    source_keys: string[];
  };
  acquired: { evidence_id: string; source_key: string; source_name: string; record_count: number; sha256_hash: string }[];
  skipped: { source_key: string; source_name: string; reason: string }[];
}
