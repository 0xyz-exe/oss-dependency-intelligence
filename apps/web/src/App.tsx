import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, ShieldCheck, Box, AlertTriangle, Scale, 
  FileText, ArrowRightLeft, Settings as SettingsIcon, 
  RefreshCw, Play, CheckCircle2, XCircle, Search, 
  Download, ExternalLink, ChevronRight, Layers, FileCode
} from 'lucide-react';
import { 
  Project, Scan, Dependency, Vulnerability, Policy, 
  PolicyEvaluation, ScanCompareResult 
} from './types';
import * as api from './api';

export function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'projects' | 'dependencies' | 'vulnerabilities' | 'licenses' | 'compare' | 'sbom' | 'policies'>('overview');
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [currentScan, setCurrentScan] = useState<Scan | null>(null);
  const [dependencies, setDependencies] = useState<Dependency[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [policyEval, setPolicyEval] = useState<PolicyEvaluation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [depSearch, setDepSearch] = useState('');
  const [depEcoFilter, setDepEcoFilter] = useState('');
  const [vulnSevFilter, setVulnSevFilter] = useState('');

  // Compare states
  const [baselineScanId, setBaselineScanId] = useState('');
  const [compareResult, setCompareResult] = useState<ScanCompareResult | null>(null);

  // New Project Modal State
  const [isNewProjectOpen, setIsNewProjectOpen] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectPath, setNewProjectPath] = useState('');

  // Load initial projects & default scan
  useEffect(() => {
    loadProjects();
    loadPolicies();
  }, []);

  async function loadProjects() {
    try {
      setLoading(true);
      const data = await api.fetchProjects();
      setProjects(data);
      if (data.length > 0 && !selectedProject) {
        selectProject(data[0]);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load projects');
    } finally {
      setLoading(false);
    }
  }

  async function loadPolicies() {
    try {
      const data = await api.fetchPolicies();
      setPolicies(data);
    } catch (err) {
      console.error(err);
    }
  }

  async function selectProject(proj: Project) {
    setSelectedProject(proj);
    if (proj.latest_scan) {
      loadScanDetails(proj.latest_scan.id);
    } else {
      setCurrentScan(null);
      setDependencies([]);
      setVulnerabilities([]);
      setPolicyEval(null);
    }
  }

  async function loadScanDetails(scanId: string) {
    try {
      setLoading(true);
      const [scanData, depsData, vulnsData, evalData] = await Promise.all([
        api.fetchScan(scanId),
        api.fetchDependencies(scanId),
        api.fetchVulnerabilities(scanId),
        api.fetchPolicyEvaluation(scanId).catch(() => null),
      ]);
      setCurrentScan(scanData);
      setDependencies(depsData);
      setVulnerabilities(vulnsData);
      setPolicyEval(evalData);
    } catch (err: any) {
      setError(err.message || 'Failed to load scan details');
    } finally {
      setLoading(false);
    }
  }

  async function handleTriggerScan() {
    if (!selectedProject) return;
    try {
      setLoading(true);
      setError(null);
      const scan = await api.triggerScan(selectedProject.id);
      await loadScanDetails(scan.id);
      await loadProjects();
    } catch (err: any) {
      setError(err.message || 'Scan trigger failed');
    } finally {
      setLoading(false);
    }
  }

  async function handleCreateProject(e: React.FormEvent) {
    e.preventDefault();
    if (!newProjectName.trim() || !newProjectPath.trim()) return;
    try {
      setLoading(true);
      const p = await api.createProject({
        name: newProjectName,
        target_path: newProjectPath,
        ecosystem: 'auto'
      });
      setIsNewProjectOpen(false);
      setNewProjectName('');
      setNewProjectPath('');
      await loadProjects();
      selectProject(p);
    } catch (err: any) {
      setError(err.message || 'Failed to create project');
    } finally {
      setLoading(false);
    }
  }

  async function handleCompare() {
    if (!baselineScanId || !currentScan) return;
    try {
      setLoading(true);
      const res = await api.compareScans(baselineScanId, currentScan.id);
      setCompareResult(res);
    } catch (err: any) {
      setError(err.message || 'Failed to compare scans');
    } finally {
      setLoading(false);
    }
  }

  // Filtered lists
  const filteredDependencies = dependencies.filter(d => {
    const matchesSearch = d.name.toLowerCase().includes(depSearch.toLowerCase());
    const matchesEco = !depEcoFilter || d.ecosystem.toLowerCase() === depEcoFilter.toLowerCase();
    return matchesSearch && matchesEco;
  });

  const filteredVulnerabilities = vulnerabilities.filter(v => {
    return !vulnSevFilter || v.severity.toUpperCase() === vulnSevFilter.toUpperCase();
  });

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-800 bg-slate-900/40 flex flex-col justify-between">
        <div>
          <div className="h-16 flex items-center gap-3 px-6 border-b border-slate-800">
            <div className="p-2 bg-sky-500/10 border border-sky-500/20 rounded-lg text-sky-400">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="font-bold text-sm tracking-wide text-slate-100">OSSDI</div>
              <div className="text-[10px] text-slate-500 tracking-wider uppercase font-semibold">Intelligence</div>
            </div>
          </div>

          {/* Project Switcher */}
          <div className="p-4 border-b border-slate-800">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Target Project</div>
            <select
              value={selectedProject?.id || ''}
              onChange={(e) => {
                const found = projects.find(p => p.id === e.target.value);
                if (found) selectProject(found);
              }}
              className="w-full bg-slate-900 border border-slate-700 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
            >
              {projects.map(p => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            <button
              onClick={() => setIsNewProjectOpen(true)}
              className="mt-2 w-full text-xs text-sky-400 hover:text-sky-300 flex items-center justify-center gap-1 py-1 rounded border border-sky-500/20 bg-sky-500/5 transition"
            >
              + Register Project
            </button>
          </div>

          {/* Navigation */}
          <nav className="p-3 space-y-1">
            {[
              { id: 'overview', label: 'Overview', icon: Layers },
              { id: 'dependencies', label: 'Dependencies', icon: Box, badge: currentScan?.total_dependencies },
              { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert, badge: currentScan?.vulnerabilities_count, badgeColor: 'bg-rose-500/20 text-rose-400' },
              { id: 'licenses', label: 'License Compliance', icon: Scale },
              { id: 'compare', label: 'Scan Comparison', icon: ArrowRightLeft },
              { id: 'sbom', label: 'SBOM Export', icon: FileCode },
              { id: 'policies', label: 'Governance Policies', icon: SettingsIcon },
            ].map(tab => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition ${
                    isActive 
                      ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20' 
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className="w-4 h-4" />
                    <span>{tab.label}</span>
                  </div>
                  {tab.badge !== undefined && tab.badge > 0 && (
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${tab.badgeColor || 'bg-slate-800 text-slate-300'}`}>
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Footer scan action */}
        <div className="p-4 border-t border-slate-800">
          <button
            onClick={handleTriggerScan}
            disabled={loading || !selectedProject}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-sm transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Run Deep Analysis</span>
          </button>
          <div className="mt-2 text-center text-[10px] text-slate-500">
            Local Engine • OSV Intelligence
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Header bar */}
        <header className="h-16 border-b border-slate-800 px-8 flex items-center justify-between bg-slate-900/20 backdrop-blur">
          <div className="flex items-center gap-4">
            <div>
              <h1 className="text-base font-bold text-slate-100 flex items-center gap-2">
                {selectedProject?.name || 'No Project Selected'}
                {policyEval && (
                  <span className={`px-2 py-0.5 text-[11px] rounded font-bold uppercase tracking-wide ${
                    policyEval.result === 'PASS' 
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' 
                      : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                  }`}>
                    Policy {policyEval.result}
                  </span>
                )}
              </h1>
              <p className="text-xs text-slate-400 truncate max-w-xl">{selectedProject?.target_path || 'Select or add a project directory to scan'}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {currentScan && (
              <div className="text-right">
                <div className="text-xs text-slate-300 font-medium">Risk Score: <span className="font-bold text-amber-400">{currentScan.risk_score}/100</span></div>
                <div className="text-[11px] text-slate-500">Scanned {currentScan.created_at} • {currentScan.duration_ms}ms</div>
              </div>
            )}
          </div>
        </header>

        {/* Global error banner */}
        {error && (
          <div className="mx-8 mt-4 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg flex items-center justify-between text-xs text-rose-300">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">Dismiss</button>
          </div>
        )}

        {/* View Switching */}
        <div className="p-8 space-y-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Metric Cards */}
              <div className="grid grid-cols-4 gap-4">
                <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                    <span>Total Dependencies</span>
                    <Box className="w-4 h-4 text-sky-400" />
                  </div>
                  <div className="text-2xl font-bold text-slate-100">{currentScan?.total_dependencies || 0}</div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    {currentScan?.direct_dependencies || 0} direct • {currentScan?.transitive_dependencies || 0} transitive
                  </div>
                </div>

                <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                    <span>Active Vulnerabilities</span>
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                  </div>
                  <div className="text-2xl font-bold text-rose-400">{currentScan?.vulnerabilities_count || 0}</div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    {currentScan?.critical_count || 0} Critical • {currentScan?.high_count || 0} High
                  </div>
                </div>

                <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                    <span>License Risk</span>
                    <Scale className="w-4 h-4 text-amber-400" />
                  </div>
                  <div className="text-2xl font-bold text-slate-100">{currentScan?.license_violations_count || 0}</div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    {currentScan?.unknown_license_count || 0} unknown licenses
                  </div>
                </div>

                <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                    <span>Supply Chain Risk</span>
                    <AlertTriangle className="w-4 h-4 text-orange-400" />
                  </div>
                  <div className="text-2xl font-bold text-amber-400">{currentScan?.risk_score || 0}<span className="text-xs text-slate-500"> /100</span></div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    Multi-factor explainable score
                  </div>
                </div>
              </div>

              {/* Policy Evaluation Banner */}
              {policyEval && (
                <div className={`p-4 rounded-xl border ${
                  policyEval.result === 'PASS' 
                    ? 'bg-emerald-950/20 border-emerald-800/40' 
                    : 'bg-rose-950/20 border-rose-800/40'
                }`}>
                  <div className="flex items-center gap-2 mb-2 font-semibold text-sm">
                    {policyEval.result === 'PASS' ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <XCircle className="w-5 h-5 text-rose-400" />
                    )}
                    <span className={policyEval.result === 'PASS' ? 'text-emerald-300' : 'text-rose-300'}>
                      {policyEval.summary}
                    </span>
                  </div>
                  {policyEval.violations.length > 0 && (
                    <ul className="mt-2 space-y-1 text-xs text-rose-300/90 pl-7 list-disc">
                      {policyEval.violations.map((v, i) => (
                        <li key={i}>{v}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* High Priority Vulnerabilities list preview */}
              <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-sm font-bold text-slate-200">High & Critical Advisories Requiring Action</h2>
                  <button onClick={() => setActiveTab('vulnerabilities')} className="text-xs text-sky-400 hover:text-sky-300">
                    View All ({vulnerabilities.length}) &rarr;
                  </button>
                </div>
                {vulnerabilities.length === 0 ? (
                  <div className="text-center py-8 text-xs text-slate-500">No known vulnerabilities detected. Clean supply chain.</div>
                ) : (
                  <div className="space-y-3">
                    {vulnerabilities.slice(0, 5).map(v => (
                      <div key={v.id} className="p-3 bg-slate-900/80 border border-slate-800 rounded-lg flex items-center justify-between text-xs">
                        <div className="space-y-1 max-w-xl">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded font-bold uppercase text-[10px] ${
                              v.severity === 'CRITICAL' ? 'bg-purple-500/20 text-purple-300' :
                              v.severity === 'HIGH' ? 'bg-rose-500/20 text-rose-300' :
                              'bg-amber-500/20 text-amber-300'
                            }`}>{v.severity}</span>
                            <span className="font-semibold text-slate-200">{v.dependency_name}@{v.installed_version}</span>
                            <span className="text-slate-500">• {v.advisory_id}</span>
                          </div>
                          <div className="text-slate-400 text-[11px] truncate">{v.summary}</div>
                        </div>
                        <div className="text-right">
                          <div className="text-[11px] text-sky-400 font-medium">{v.remediation_advice}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'dependencies' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between gap-4">
                <div className="relative flex-1 max-w-md">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder="Search package by name..."
                    value={depSearch}
                    onChange={e => setDepSearch(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <select
                    value={depEcoFilter}
                    onChange={e => setDepEcoFilter(e.target.value)}
                    className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                  >
                    <option value="">All Ecosystems</option>
                    <option value="npm">npm / Node.js</option>
                    <option value="pypi">PyPI / Python</option>
                    <option value="composer">Composer / PHP</option>
                    <option value="crates.io">Cargo / Rust</option>
                    <option value="go">Go Modules</option>
                  </select>
                </div>
              </div>

              <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                    <tr>
                      <th className="py-3 px-4">Package</th>
                      <th className="py-3 px-4">Version</th>
                      <th className="py-3 px-4">Ecosystem</th>
                      <th className="py-3 px-4">Direct / Transitive</th>
                      <th className="py-3 px-4">License</th>
                      <th className="py-3 px-4">Vulnerabilities</th>
                      <th className="py-3 px-4">Risk Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredDependencies.map(d => (
                      <tr key={d.id} className="hover:bg-slate-900/50 transition">
                        <td className="py-3 px-4 font-semibold text-slate-200">{d.name}</td>
                        <td className="py-3 px-4 font-mono text-slate-300">{d.version}</td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] uppercase font-bold">{d.ecosystem}</span>
                        </td>
                        <td className="py-3 px-4 text-slate-400">
                          {d.is_direct ? 'Direct' : 'Transitive'}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                            d.license_status === 'allowed' ? 'bg-emerald-500/10 text-emerald-400' :
                            d.license_status === 'restricted' ? 'bg-rose-500/10 text-rose-400' :
                            'bg-slate-800 text-slate-400'
                          }`}>
                            {d.detected_license || 'Unknown'}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          {d.vulnerability_count > 0 ? (
                            <span className="text-rose-400 font-bold">{d.vulnerability_count} findings ({d.max_severity})</span>
                          ) : (
                            <span className="text-emerald-400">0 clean</span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-bold text-amber-400">{d.risk_score}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'vulnerabilities' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="text-xs text-slate-400">
                  Showing {filteredVulnerabilities.length} active advisories
                </div>
                <select
                  value={vulnSevFilter}
                  onChange={e => setVulnSevFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                >
                  <option value="">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <div className="space-y-3">
                {filteredVulnerabilities.map(v => (
                  <div key={v.id} className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-3">
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded font-bold uppercase text-[10px] ${
                            v.severity === 'CRITICAL' ? 'bg-purple-500/20 text-purple-300' :
                            v.severity === 'HIGH' ? 'bg-rose-500/20 text-rose-300' :
                            'bg-amber-500/20 text-amber-300'
                          }`}>{v.severity}</span>
                          <span className="font-bold text-slate-100 text-sm">{v.advisory_id}</span>
                          <span className="text-slate-400 text-xs">({v.dependency_name} @ {v.installed_version})</span>
                        </div>
                        <h3 className="text-xs font-semibold text-slate-200">{v.summary}</h3>
                      </div>
                      <div className="text-right">
                        <span className="px-2.5 py-1 rounded-full text-[10px] font-semibold uppercase bg-slate-800 text-slate-300">
                          Status: {v.status}
                        </span>
                      </div>
                    </div>

                    {v.details && (
                      <p className="text-xs text-slate-400 bg-slate-950/60 p-3 rounded-lg font-mono border border-slate-800/80 leading-relaxed">
                        {v.details}
                      </p>
                    )}

                    <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800/60">
                      <div className="text-sky-400 font-medium">
                        Remediation: {v.remediation_advice}
                      </div>
                      {v.references && v.references.length > 0 && (
                        <a
                          href={v.references[0]}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center gap-1 text-slate-400 hover:text-slate-200"
                        >
                          <span>Upstream Advisory</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'licenses' && (
            <div className="space-y-6">
              <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
                <h2 className="text-sm font-bold text-slate-200 mb-2">SPDX License Distribution & Compliance</h2>
                <p className="text-xs text-slate-400 mb-4">
                  Evaluated using SPDX-2.3 expressions against active project distribution policies.
                </p>
                <div className="space-y-2">
                  {dependencies.map(d => (
                    <div key={d.id} className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between text-xs">
                      <div>
                        <span className="font-semibold text-slate-200">{d.name}</span>
                        <span className="text-slate-500 ml-2">({d.ecosystem})</span>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className="text-slate-400 font-mono">{d.detected_license || 'Unknown'}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          d.license_status === 'allowed' ? 'bg-emerald-500/20 text-emerald-300' :
                          d.license_status === 'restricted' ? 'bg-rose-500/20 text-rose-300' :
                          'bg-amber-500/20 text-amber-300'
                        }`}>{d.license_status}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'compare' && (
            <div className="space-y-6">
              <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-4">
                <h2 className="text-sm font-bold text-slate-200">Compare Scan Against Baseline</h2>
                <div className="flex items-center gap-3">
                  <input
                    type="text"
                    placeholder="Enter baseline scan ID (e.g. scan-abcdef1234)..."
                    value={baselineScanId}
                    onChange={e => setBaselineScanId(e.target.value)}
                    className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                  />
                  <button
                    onClick={handleCompare}
                    disabled={!baselineScanId}
                    className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold disabled:opacity-50 transition"
                  >
                    Run Diff
                  </button>
                </div>
              </div>

              {compareResult && (
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="text-xs text-slate-300 font-medium">
                    Risk Score Delta: <span className="font-bold text-amber-400">{compareResult.risk_score_delta}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-xs">
                    <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
                      <div className="font-bold text-slate-200 mb-2">New Vulnerabilities ({compareResult.new_vulnerabilities.length})</div>
                      {compareResult.new_vulnerabilities.map((v, i) => (
                        <div key={i} className="text-rose-400 py-1">{v.dependency} - {v.advisory_id}</div>
                      ))}
                    </div>
                    <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
                      <div className="font-bold text-slate-200 mb-2">Resolved Vulnerabilities ({compareResult.resolved_vulnerabilities.length})</div>
                      {compareResult.resolved_vulnerabilities.map((v, i) => (
                        <div key={i} className="text-emerald-400 py-1">{v.dependency} - {v.advisory_id}</div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'sbom' && currentScan && (
            <div className="space-y-6">
              <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-4">
                <h2 className="text-sm font-bold text-slate-200">Software Bill of Materials (SBOM) Generation</h2>
                <p className="text-xs text-slate-400">
                  Export machine-readable SBOM standards compliant with US Executive Order 14028.
                </p>
                <div className="flex items-center gap-4">
                  <a
                    href={`/api/v1/scans/${currentScan.id}/sbom?format=cyclonedx-json`}
                    download={`cyclonedx-${currentScan.id}.json`}
                    className="flex items-center gap-2 px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold transition"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download CycloneDX 1.5 JSON</span>
                  </a>
                  <a
                    href={`/api/v1/scans/${currentScan.id}/sbom?format=spdx-json`}
                    download={`spdx-${currentScan.id}.json`}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download SPDX 2.3 JSON</span>
                  </a>
                  <a
                    href={`/api/v1/scans/${currentScan.id}/report?format=csv`}
                    download={`report-${currentScan.id}.csv`}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download CSV Audit Report</span>
                  </a>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'policies' && (
            <div className="space-y-6">
              <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-4">
                <h2 className="text-sm font-bold text-slate-200">Security & Compliance Policies</h2>
                <div className="space-y-3">
                  {policies.map(p => (
                    <div key={p.id} className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg text-xs space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-100">{p.name}</span>
                        {p.is_default && (
                          <span className="px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 font-semibold text-[10px] uppercase">Default</span>
                        )}
                      </div>
                      <p className="text-slate-400">{p.description}</p>
                      <div className="flex items-center gap-4 text-[11px] text-slate-500 pt-1">
                        <span>Fail Severity: <strong className="text-slate-300">{p.fail_on_severity}</strong></span>
                        <span>Copyleft Block: <strong className="text-slate-300">{p.block_copyleft ? 'Yes' : 'No'}</strong></span>
                        <span>Unknown License Block: <strong className="text-slate-300">{p.block_unknown_license ? 'Yes' : 'No'}</strong></span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* New Project Modal */}
      {isNewProjectOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4">
            <h2 className="text-sm font-bold text-slate-100">Register New Project</h2>
            <form onSubmit={handleCreateProject} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Project Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. My Backend API"
                  value={newProjectName}
                  onChange={e => setNewProjectName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Local Directory or Manifest Path</label>
                <input
                  type="text"
                  required
                  placeholder="C:/Users/.../my-app"
                  value={newProjectPath}
                  onChange={e => setNewProjectPath(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                />
              </div>
              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsNewProjectOpen(false)}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold disabled:opacity-50"
                >
                  Register & Inspect
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
