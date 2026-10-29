"""Pydantic schemas for API and internal data representations."""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class DependencyItem(BaseModel):
    name: str
    version: str
    ecosystem: str
    purl: str
    is_direct: bool = True
    declared_constraint: Optional[str] = None
    depth: int = 1
    parent_name: Optional[str] = None
    source_file: Optional[str] = None
    declared_license: Optional[str] = None
    detected_license: Optional[str] = None
    license_category: Optional[str] = None
    license_status: str = "allowed"
    vulnerability_count: int = 0
    max_severity: str = "NONE"
    risk_score: float = 0.0
    confidence: float = 1.0

class VulnerabilityItem(BaseModel):
    dependency_name: str
    installed_version: str
    ecosystem: str
    purl: str
    advisory_id: str
    cve_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    osv_id: Optional[str] = None
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    vulnerable_range: Optional[str] = None
    fixed_version: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    source: str = "OSV"
    status: str = "open"
    remediation_advice: Optional[str] = None

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    ecosystem: Optional[str] = "multi"
    repository_url: Optional[str] = ""
    target_path: Optional[str] = ""

class ProjectOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = ""
    ecosystem: Optional[str] = ""
    repository_url: Optional[str] = ""
    target_path: Optional[str] = ""
    created_at: str
    updated_at: str
    latest_scan: Optional[Dict[str, Any]] = None

class ScanOut(BaseModel):
    id: str
    project_id: str
    status: str
    scan_target: str
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    total_dependencies: int
    direct_dependencies: int
    transitive_dependencies: int
    vulnerabilities_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    license_violations_count: int
    unknown_license_count: int
    risk_score: float
    duration_ms: int
    error_message: Optional[str] = None
    created_at: str

class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    is_default: bool = False
    fail_on_severity: str = "HIGH"
    max_high_count: int = 0
    block_copyleft: bool = False
    block_unknown_license: bool = False
    require_fix_available: bool = False
    allowed_licenses: List[str] = Field(default_factory=list)
    denied_licenses: List[str] = Field(default_factory=list)

class PolicyOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = ""
    is_default: bool
    fail_on_severity: str
    max_high_count: int
    block_copyleft: bool
    block_unknown_license: bool
    require_fix_available: bool
    allowed_licenses: List[str] = Field(default_factory=list)
    denied_licenses: List[str] = Field(default_factory=list)
    created_at: str

class PolicyEvaluationResult(BaseModel):
    scan_id: str
    policy_id: str
    result: str # PASS, WARN, FAIL, INCOMPLETE
    violations: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    summary: str

class ScanCompareRequest(BaseModel):
    baseline_scan_id: str
    current_scan_id: str

class ScanCompareResult(BaseModel):
    baseline_scan_id: str
    current_scan_id: str
    added_dependencies: List[Dict[str, Any]]
    removed_dependencies: List[Dict[str, Any]]
    version_changes: List[Dict[str, Any]]
    new_vulnerabilities: List[Dict[str, Any]]
    resolved_vulnerabilities: List[Dict[str, Any]]
    license_changes: List[Dict[str, Any]]
    risk_score_delta: float
