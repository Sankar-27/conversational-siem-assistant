export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user_id: string;
  name: string;
  email: string;
  role: UserRole;
}

export interface IOC {
  type: string;
  value: string;
  occurrence_count: number;
  is_internal?: boolean;
  flagged?: boolean;
}

export interface AttackPattern {
  pattern_type: string;
  source_ip: string | null;
  confidence: number;
  evidence_count: number;
  details: Record<string, any>;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface MITRETechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  sub_technique_id?: string | null;
  sub_technique_name?: string | null;
  confidence: number;
  evidence_count: number;
  description: string;
  source_pattern: string;
}

export interface TimelineEvent {
  timestamp: string;
  event_action: string;
  source_ip: string | null;
  username: string | null;
  description: string;
  phase: string;
  severity: number;
  log_id?: string | null;
}

export interface TimelineSummary {
  phase_sequence: string[];
  duration_seconds: number;
  total_events: number;
  first_event?: string | null;
  last_event?: string | null;
}

export interface AgentStageOutput {
  stage_number: number;
  stage_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  duration_ms: number;
  summary: string;
  details: Record<string, any>;
}

export interface ThreeStageInvestigationResult {
  investigation_id: string;
  conversation_id: string;
  nl_query: string;
  status: 'completed' | 'ambiguous' | 'failed' | 'error';
  total_duration_ms: number;
  stages: AgentStageOutput[];
  entities: Record<string, any>;
  generated_dsl: Record<string, any>;
  retrieved_logs_count: number;
  retrieved_logs: Array<Record<string, any>>;
  rag_threat_context: Array<Record<string, any>>;
  matched_patterns: AttackPattern[];
  mitre_tactics: MITRETechnique[];
  iocs: IOC[];
  timeline: TimelineEvent[];
  severity_assessment: SeverityScore | Record<string, any>;
  conversational_response: string;
  confirmed_evidence: string[];
  assumptions_and_hypotheses: string[];
  remediation_recommendations: string[];
  confidence: 'High' | 'Medium' | 'Low';
}

export interface InvestigationResponse {
  investigation_id: string;
  conversation_id: string;
  nl_query: string;
  intent?: string;
  generated_query_ir?: Record<string, any>;
  elasticsearch_query?: Record<string, any>;
  generated_dsl?: Record<string, any>;
  result_count?: number;
  retrieved_logs_count?: number;
  hits_preview?: Array<Record<string, any>>;
  retrieved_logs?: Array<Record<string, any>>;
  iocs: IOC[];
  patterns?: AttackPattern[];
  matched_patterns?: AttackPattern[];
  mitre?: MITRETechnique[];
  mitre_tactics?: MITRETechnique[];
  timeline: TimelineEvent[];
  timeline_summary?: TimelineSummary;
  explanation?: string;
  conversational_response?: string;
  status: 'completed' | 'failed' | 'ambiguous' | 'running' | 'pending';
  ambiguous?: boolean;
  clarification_needed?: string | null;
  validation_errors?: string[];
  knowledge_evidence?: KnowledgeEvidence[];
  rag_threat_context?: Array<Record<string, any>>;
  siem_evidence?: SiemEvidence[];
  attack_chain?: AttackChain;
  severity?: SeverityScore;
  severity_assessment?: SeverityScore | Record<string, any>;
  entity_graph?: EntityGraph;
  stages?: AgentStageOutput[];
  total_duration_ms?: number;
  confirmed_evidence?: string[];
  assumptions_and_hypotheses?: string[];
  remediation_recommendations?: string[];
  confidence?: 'High' | 'Medium' | 'Low';
}

export interface KnowledgeEvidence {
  chunk_id: string;
  title: string;
  text: string;
  source: string;
  doc_type: string;
  doc_id: string;
  score: number;
  evidence_type: 'knowledge_base';
}

export interface SiemEvidence {
  log_id: string;
  evidence_type: 'siem';
  preview: Record<string, any>;
}

export interface AttackChain {
  source_ip: string | null;
  chain: Array<{
    phase: string;
    pattern: string;
    source_ip: string | null;
    evidence_count: number;
    confidence: number;
  }>;
  phase_sequence: string[];
  evidence_backed: boolean;
}

export interface SeverityScore {
  score: number;
  level: string;
  factors: Array<{ pattern: string; weight: number; contribution: number }>;
}

export interface EntityGraph {
  nodes: Array<{ id: string; type: string; event_count?: number }>;
  edges: Array<{ source: string; target: string; relation: string }>;
  stats: { unique_ips: number; unique_users: number };
}

export interface MCPToolCall {
  tool_name: string;
  arguments?: Record<string, any>;
  result_summary: string;
  duration_ms?: number;
  status: 'completed' | 'failed' | 'blocked';
}

export interface ThreatAssessment {
  observed_evidence: SiemEvidence[];
  retrieved_knowledge: KnowledgeEvidence[];
  ai_assessment: string;
  confidence: 'High' | 'Medium' | 'Low';
}

export interface AgentInvestigationResponse {
  investigation_id: string;
  conversation_id: string;
  nl_query: string;
  status: 'completed' | 'failed' | 'ambiguous' | 'running' | 'awaiting_approval' | 'timeout';
  plan: string[];
  tool_calls: MCPToolCall[];
  siem_evidence: SiemEvidence[];
  knowledge_evidence: KnowledgeEvidence[];
  iocs: IOC[];
  patterns: AttackPattern[];
  mitre: MITRETechnique[];
  timeline: TimelineEvent[];
  conclusion: string;
  threat_assessment?: ThreatAssessment;
  attack_chain?: AttackChain;
  severity?: SeverityScore;
  pending_approval?: {
    planned_steps: string[];
    tools: string[];
    scope?: Record<string, any>;
  };
  approval_token?: string;
}

export interface ObservabilityMetrics {
  total_investigations: number;
  completed_investigations: number;
  failed_investigations: number;
  success_rate: number;
  tool_call_counts: Record<string, number>;
  tool_average_latency_ms: Record<string, number>;
}

export interface InvestigationSummaryItem {
  id: string;
  conversation_id: string;
  nl_query: string;
  result_count: number;
  status: string;
  created_at: string;
}

export interface DashboardStats {
  total_investigations: number;
  completed_investigations: number;
  total_iocs: number;
  total_mitre_techniques: number;
  total_evidence_analyzed: number;
  failed_login_count: number;
  unique_source_ips: number;
  recent_investigations: Array<{
    id: string;
    query: string;
    result_count: number;
    status: string;
    created_at: string;
  }>;
  top_mitre_techniques: Array<{
    technique_id: string;
    technique_name: string;
    count: number;
  }>;
  top_source_ips: Array<{
    ip: string;
    count: number;
  }>;
  siem_health: {
    status: string;
    mode: string;
    total_logs?: number;
  };
}

export interface IncidentReport {
  report_id: string;
  investigation_id: string;
  generated_at: string;
  analyst: string;
  executive_summary: string;
  investigation: {
    title: string;
    analyst_query: string;
    generated_query_ir: Record<string, any>;
    elasticsearch_dsl: Record<string, any>;
    total_events_matched: number;
    events_analyzed: number;
    time_range: {
      from: string | null;
      to: string | null;
    };
  };
  evidence: Array<{
    log_id: string;
    timestamp: string;
    source_ip: string;
    username: string;
    event_action: string;
    http_status: number | string;
    url: string;
    severity: number;
  }>;
  iocs: IOC[];
  attack_analysis: {
    patterns: AttackPattern[];
    mitre_techniques: MITRETechnique[];
  };
  timeline: {
    summary: TimelineSummary;
    events: TimelineEvent[];
  };
  explanation: string;
  recommendations: string[];
}
