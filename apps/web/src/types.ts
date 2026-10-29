export interface Project {
  id: string;
  name: string;
  description: string;
  ecosystem: string;
  repository_url: string;
  target_path: string;
  created_at: string;
  updated_at: string;
  latest_scan?: Scan | null;
}

export interface Scan {
  id: string;
  project_id: string;
  status: string;
  scan_target: string;
  branch?: string;
  commit_hash?: string;
  total_dependencies: number;
  direct_dependencies: number;
  transitive_dependencies: number;
  vulnerabilities_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  license_violations_count: number;
  unknown_license_count: number;
  risk_score: number;
  duration_ms: number;
  error_message?: string;
  created_at: string;
}

export interface Dependency {
  id: string;
  scan_id: string;
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  is_direct: boolean;
  declared_constraint?: string;
  depth: number;
  parent_name?: string;
  source_file?: string;
  declared_license?: string;
  detected_license?: string;
  license_category?: string;
  license_status: string;
  vulnerability_count: number;
  max_severity: string;
  risk_score: number;
  confidence: number;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  dependency_name: string;
  installed_version: string;
  ecosystem: string;
  purl: string;
  advisory_id: string;
  cve_id?: string;
  ghsa_id?: string;
  osv_id?: string;
  summary?: string;
  details?: string;
  severity: string;
  cvss_score?: number;
  vulnerable_range?: string;
  fixed_version?: string;
  references: string[];
  source: string;
  status: string;
  remediation_advice?: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  is_default: boolean;
  fail_on_severity: string;
  max_high_count: number;
  block_copyleft: boolean;
  block_unknown_license: boolean;
  require_fix_available: boolean;
  allowed_licenses: string[];
  denied_licenses: string[];
  created_at: string;
}

export interface PolicyEvaluation {
  scan_id: string;
  policy_id: string;
  result: 'PASS' | 'WARN' | 'FAIL' | 'INCOMPLETE';
  violations: string[];
  warnings: string[];
  summary: string;
}

export interface ScanCompareResult {
  baseline_scan_id: string;
  current_scan_id: string;
  added_dependencies: Array<{ name: string; version: string; ecosystem: string; license?: string }>;
  removed_dependencies: Array<{ name: string; version: string; ecosystem: string }>;
  version_changes: Array<{ name: string; old_version: string; new_version: string; ecosystem: string }>;
  new_vulnerabilities: Array<{ dependency: string; version: string; advisory_id: string; severity: string; summary?: string }>;
  resolved_vulnerabilities: Array<{ dependency: string; version: string; advisory_id: string; severity: string; summary?: string }>;
  license_changes: Array<{ name: string; old_license?: string; new_license?: string }>;
  risk_score_delta: number;
}
