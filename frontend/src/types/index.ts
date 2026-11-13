export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Role = "administrator" | "security_analyst" | "penetration_tester" | "auditor";
export type ScannerType = "nmap" | "openvas" | "nessus" | "nuclei" | "custom" | "import";
export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type VulnStatus = "open" | "triaged" | "remediated" | "false_positive" | "risk_accepted";

export interface User {
  id: number;
  username: string;
  email: string | null;
  role: Role;
  is_active: boolean;
  created_at: string;
}
export interface Asset {
  id: number;
  ip_address: string;
  hostname: string | null;
  os_name: string | null;
  criticality: string;
  internet_exposed: boolean;
  tags: string[];
  first_seen: string;
  last_seen: string;
  vulnerability_count: number;
  max_risk_score: number;
  port_count: number;
}

export interface Vulnerability {
  id: number;
  title: string;
  severity: Severity;
  cvss_score: number | null;
  risk_score: number;
  cve_ids: string[];
  cwe_ids: string[];
  capec_ids: string[];
  attack_techniques: string[];
  owasp_categories: string[];
  exploit_available: boolean;
  kev_listed: boolean;
  status: VulnStatus;
  source_scanners: string[];
  asset_ip: string | null;
  asset_id: number;
  port: number | null;
  first_seen: string;
  last_seen: string;
  assigned_to: string | null;
}

export interface Scan {
  id: number;
  name: string;
  scanner_type: ScannerType;
  target: string;
  status: ScanStatus;
  progress_pct: number;
  started_at: string | null;
  finished_at: string | null;
  created_by: string | null;
  findings_count: number;
  error_message: string | null;
}

export interface DashboardStats {
  total_assets: number;
  total_vulnerabilities: number;
  total_scans: number;
  internet_exposed_assets: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  kev_count: number;
  exploitable_count: number;
  risk_heatmap: { criticality: string; severity: string; count: number }[];
  technique_heatmap: { technique: string; name: string; tactic: string; count: number }[];
  recent_scans: { id: number; name: string; scanner_type: string; status: string; findings_count: number }[];
}

export interface AssistantResponse {
  answer: string;
  sources: { id?: string; source: string; title: string; relevance: number }[];
  structured_results: any[];
  provider?: string;
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  sources?: { id?: string; source: string; title: string; relevance: number }[];
}

export type RAGStatus = AssistantStatus;
export type ReportRecord = ReportJob;

export interface AssistantStatus {
  generation: { mode: string; name: string; provider: string; model: string | null; status: string };
  embedding: { model: string; revision: string | null; device: string; active: { dimension: number; provider: string }; index: { state: string; legacy_vectors?: number; incompatible_vectors?: number } };
  retrieval: { dense: boolean; bm25: boolean; rrf: boolean; dense_top_k: number; sparse_top_k: number; rrf_k: number; final_evidence_k: number };
  reranker: { provider: string; model: string; loaded: boolean };
  jev: { mode: string; model: string; status: string; warning?: string };
  index: { knowledge_documents: number; knowledge_chunks: number; state: string };
}

export interface KnowledgeDoc {
  id: number;
  title: string;
  category: string;
  tags: string[];
  created_by: string | null;
  updated_at: string;
  chunk_count?: number;
  indexed_chunk_count?: number;
  source_filename?: string | null;
}

export interface ReportJob {
  id: number;
  report_type: string;
  report_format: string;
  scope_description: string | null;
  generated_by: string | null;
  generated_at: string;
  compliance_framework: string | null;
}

export interface ScanSchedule {
  id: number;
  name: string;
  scanner_type: ScannerType;
  target: string;
  frequency: string;
  cron_expression: string | null;
  enabled: boolean;
  rescan_on_remediation: boolean;
  last_run: string | null;
  next_run: string | null;
}

export type IOCType = "ip" | "domain" | "url" | "hash" | "cve";

export interface IOC {
  id: number;
  ioc_type: IOCType;
  value: string;
  threat_actor: string | null;
  campaign: string | null;
  source: string | null;
  related_cves: string[];
  confidence: string;
  notes: string | null;
  latitude: number | null;
  longitude: number | null;
  country: string | null;
  city: string | null;
  created_by: string | null;
  created_at: string;
}

export interface MapPoint {
  id: number;
  value: string;
  lat: number;
  lon: number;
  country: string | null;
  city: string | null;
  threat_actor: string | null;
  campaign: string | null;
  confidence: string;
}

export interface ExposureMatch {
  cve: string;
  ioc_id: number;
  ioc_value: string;
  ioc_type: IOCType;
  threat_actor: string | null;
  campaign: string | null;
  vulnerability_id: number;
  vulnerability_title: string;
  severity: Severity;
  status: VulnStatus;
  asset_id: number;
}

export type PipelineTier = "confirmed_active_targeted" | "confirmed_active" | "adversary_observed" | "dormant_exploit" | "no_known_exploit";

export interface PipelineIOCMatch {
  ioc_id: number;
  value: string;
  threat_actor: string | null;
  campaign: string | null;
  matched_cve: string;
}

export interface PipelineVuln {
  vulnerability_id: number;
  title: string;
  cve_ids: string[];
  severity: Severity;
  status: VulnStatus;
  risk_score: number;
  kev_listed: boolean;
  exploit_available: boolean;
  adversary_observed: boolean;
  matched_iocs: PipelineIOCMatch[];
  tier: PipelineTier;
}

export interface PipelineAsset {
  asset_id: number;
  ip_address: string;
  hostname: string | null;
  criticality: string | null;
  vulnerabilities: PipelineVuln[];
}

export interface ExploitPipeline {
  overall: {
    tier_counts: Record<PipelineTier, number>;
    total_vulnerabilities: number;
    assets_affected: number;
  };
  assets: PipelineAsset[];
}

export interface ExploitDBEntry {
  edb_id: string | null;
  title: string | null;
  type: string | null;
  platform: string | null;
  date: string | null;
  verified: boolean;
  path: string | null;
}

export interface ExploitScanResult {
  cve: string;
  vulnerability_id: number;
  vulnerability_title: string;
  asset_id: number;
  severity: Severity;
  kev_listed: boolean;
  maturity: "active" | "dormant";
  exploit_count: number;
  exploits: ExploitDBEntry[];
}

export interface AuditEntry {
  id: number;
  username: string;
  action: string;
  target: string;
  details: string;
  ip_address: string;
  timestamp: string;
}

export type OpsMarkerType = "threat" | "caution" | "planning" | "observation";
export type OpsArrowType = "movement" | "attack";

export interface OpsMarker {
  id: number;
  grid_id: string;
  latitude: number;
  longitude: number;
  marker_type: OpsMarkerType;
  title: string;
  notes: string | null;
  altitude: number | null;
  source_label: string | null;
  created_by: string | null;
  created_at: string;
}

export interface OpsArrow {
  id: number;
  arrow_type: OpsArrowType;
  label: string | null;
  start_lat: number;
  start_lon: number;
  end_lat: number;
  end_lon: number;
  notes: string | null;
  created_by: string | null;
  created_at: string;
}
