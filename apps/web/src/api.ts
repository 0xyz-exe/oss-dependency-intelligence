import { Project, Scan, Dependency, Vulnerability, Policy, PolicyEvaluation, ScanCompareResult } from './types';

const API_BASE = '/api/v1';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchProjects(): Promise<Project[]> {
  const res = await fetch(`${API_BASE}/projects`);
  if (!res.ok) throw new Error('Failed to fetch projects');
  return res.json();
}

export async function createProject(data: Partial<Project>): Promise<Project> {
  const res = await fetch(`${API_BASE}/projects`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to create project');
  return res.json();
}

export async function deleteProject(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/projects/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete project');
}

export async function triggerScan(projectId: string, targetPath?: string): Promise<Scan> {
  const url = targetPath 
    ? `${API_BASE}/projects/${projectId}/scans?target_path=${encodeURIComponent(targetPath)}`
    : `${API_BASE}/projects/${projectId}/scans`;
  const res = await fetch(url, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Scan failed' }));
    throw new Error(err.detail || 'Scan failed');
  }
  return res.json();
}

export async function fetchScan(scanId: string): Promise<Scan> {
  const res = await fetch(`${API_BASE}/scans/${scanId}`);
  if (!res.ok) throw new Error('Failed to fetch scan');
  return res.json();
}

export async function fetchDependencies(
  scanId: string,
  params?: { query?: string; ecosystem?: string; is_direct?: boolean; license_status?: string }
): Promise<Dependency[]> {
  const query = new URLSearchParams();
  if (params?.query) query.set('query', params.query);
  if (params?.ecosystem) query.set('ecosystem', params.ecosystem);
  if (params?.is_direct !== undefined) query.set('is_direct', String(params.is_direct));
  if (params?.license_status) query.set('license_status', params.license_status);

  const res = await fetch(`${API_BASE}/scans/${scanId}/dependencies?${query.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch dependencies');
  return res.json();
}

export async function fetchVulnerabilities(
  scanId: string,
  params?: { severity?: string; status?: string }
): Promise<Vulnerability[]> {
  const query = new URLSearchParams();
  if (params?.severity) query.set('severity', params.severity);
  if (params?.status) query.set('status', params.status);

  const res = await fetch(`${API_BASE}/scans/${scanId}/vulnerabilities?${query.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch vulnerabilities');
  return res.json();
}

export async function updateVulnerabilityStatus(
  scanId: string,
  vulnId: string,
  status: string
): Promise<void> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/vulnerabilities/${vulnId}?status=${status}`, {
    method: 'PATCH',
  });
  if (!res.ok) throw new Error('Failed to update vulnerability status');
}

export async function fetchLicensesSummary(scanId: string): Promise<{ summary: Array<{ detected_license: string; license_category: string; license_status: string; count: number }> }> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/licenses`);
  if (!res.ok) throw new Error('Failed to fetch licenses');
  return res.json();
}

export async function fetchSbom(scanId: string, format: 'cyclonedx-json' | 'spdx-json') {
  const res = await fetch(`${API_BASE}/scans/${scanId}/sbom?format=${format}`);
  if (!res.ok) throw new Error('Failed to fetch SBOM');
  return res.json();
}

export async function fetchPolicyEvaluation(scanId: string, policyId?: string): Promise<PolicyEvaluation> {
  const url = policyId
    ? `${API_BASE}/scans/${scanId}/policy-evaluation?policy_id=${policyId}`
    : `${API_BASE}/scans/${scanId}/policy-evaluation`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to evaluate policy');
  return res.json();
}

export async function fetchPolicies(): Promise<Policy[]> {
  const res = await fetch(`${API_BASE}/policies`);
  if (!res.ok) throw new Error('Failed to fetch policies');
  return res.json();
}

export async function createPolicy(data: Partial<Policy>): Promise<Policy> {
  const res = await fetch(`${API_BASE}/policies`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to create policy');
  return res.json();
}

export async function compareScans(baselineScanId: string, currentScanId: string): Promise<ScanCompareResult> {
  const res = await fetch(`${API_BASE}/scans/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      baseline_scan_id: baselineScanId,
      current_scan_id: currentScanId,
    }),
  });
  if (!res.ok) throw new Error('Failed to compare scans');
  return res.json();
}
