export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus =
  | "open"
  | "confirmed"
  | "in_progress"
  | "resolved"
  | "accepted_risk"
  | "false_positive";
export type Category = "sast" | "secrets" | "dependencies" | "iac" | "privacy";
export interface Summary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  score: number;
}
export interface Engine {
  name: string;
  status: string;
  findings: number;
  message: string;
}
export interface Finding {
  id: string;
  fingerprint: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  scanner: string;
  file: string;
  line_start: number;
  line_end: number;
  language: string;
  confidence: number;
  cwe?: string;
  owasp?: string;
  cvss?: number;
  cve?: string;
  epss?: number;
  kev?: boolean;
  sentri_score: number;
  status: FindingStatus;
  evidence: string;
  remediation: string;
  references: string[];
  data_flow: { label: string; kind: string; file?: string; line?: number }[];
  package?: { name: string; version: string; ecosystem?: string };
  first_seen?: string;
  last_seen?: string;
}
export interface Dependency {
  name: string;
  version: string;
  ecosystem?: string;
  purl?: string;
  direct?: boolean;
  file?: string;
}
export interface Scan {
  id: string;
  repository_id: string;
  repository_name: string;
  status: "queued" | "running" | "completed" | "failed";
  mode: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  stage?: string;
  error?: string;
  summary?: Summary;
  files_scanned?: number;
  languages?: Record<string, number>;
  engines?: Engine[];
  warnings?: string[];
  duration_ms?: number;
  findings?: Finding[];
  dependencies?: Dependency[];
  policy?: { passed: boolean; violations: string[]; coverage_complete: boolean; config: Policy };
}
export interface Repository {
  id: string;
  name: string;
  source: string;
  url?: string;
  created_at: string;
  scan_count: number;
  latest_scan?: Scan;
}
export interface Settings {
  ai_configured: boolean;
  github_configured: boolean;
  network_enabled: boolean;
  external_enabled: boolean;
  auth_required: boolean;
  version?: string;
  [key: string]: unknown;
}
export interface Session {
  authenticated: boolean;
  login_required: boolean;
  user?: { name: string; login: string };
  github_configured: boolean;
}
export interface Audit {
  id: string;
  action: string;
  resource: string;
  created_at: string;
  detail: string | Record<string, unknown>;
}
export interface Policy {
  fail_on: string[];
  max_high: number;
  fail_on_secrets: boolean;
}
export interface Analysis {
  provider: string;
  analysis: string;
  patch?: string;
  tests?: string;
  warning?: string;
}
export interface Comparison {
  new: Finding[];
  resolved: Finding[];
  unchanged: number;
}
