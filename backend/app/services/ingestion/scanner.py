"""Safe repository and manifest ingestion scanner."""
import os
import time
import uuid
import zipfile
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.schemas.models import DependencyItem, VulnerabilityItem, ScanOut
from backend.app.services.parsers.manager import parser_registry
from backend.app.services.licenses.analyzer import license_analyzer
from backend.app.services.vulnerability.osv_provider import osv_provider
from backend.app.services.risk.scoring import risk_scorer
from backend.app.services.policies.engine import policy_engine

logger = logging.getLogger(__name__)

EXCLUDED_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", ".venv", "venv",
    "__pycache__", ".pytest_cache", "target", "dist", "build", ".next",
    ".cache", ".idea", ".vscode"
}

ALLOWED_MANIFEST_FILENAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "pipfile.lock", "poetry.lock",
    "composer.json", "composer.lock",
    "cargo.toml", "cargo.lock",
    "go.mod", "go.sum"
}

class IngestionScanner:
    def scan_path(self, target_path: str, project_id: Optional[str] = None, project_name: str = "Local Scan") -> ScanOut:
        """Execute a full dependency intelligence scan on a directory or file."""
        start_time = time.time()
        path_obj = Path(target_path).resolve()

        if not path_obj.exists():
            raise ValueError(f"Target path does not exist: {target_path}")

        # Ensure project exists
        p_id = project_id or f"proj-{uuid.uuid4().hex[:8]}"
        with get_db() as conn:
            cur = conn.execute("SELECT id FROM projects WHERE id = ?;", (p_id,))
            if not cur.fetchone():
                conn.execute(
                    "INSERT INTO projects (id, name, description, target_path) VALUES (?, ?, ?, ?);",
                    (p_id, project_name, f"Scanned from {path_obj.name}", str(path_obj))
                )

        scan_id = f"scan-{uuid.uuid4().hex[:10]}"
        
        # 1. Discover and parse manifests
        discovered_deps: List[DependencyItem] = []
        if path_obj.is_file():
            if path_obj.suffix.lower() == ".zip":
                discovered_deps = self._scan_zip(path_obj)
            else:
                discovered_deps = self._scan_single_file(path_obj)
        else:
            discovered_deps = self._scan_directory(path_obj)

        deduped_deps = parser_registry.deduplicate_dependencies(discovered_deps)

        # 2. License normalization & initial analysis
        for dep in deduped_deps:
            norm_lic, category, status = license_analyzer.normalize_license(dep.declared_license, dep.name)
            dep.detected_license = norm_lic
            dep.license_category = category
            dep.license_status = status

        # 3. Query Vulnerability Intelligence (OSV Batch)
        vuln_map = osv_provider.query_vulnerabilities(deduped_deps)
        all_vulns: List[VulnerabilityItem] = []

        # 4. Risk scoring per dependency
        for dep in deduped_deps:
            dep_vulns = vuln_map.get(dep.purl, [])
            dep.vulnerability_count = len(dep_vulns)
            all_vulns.extend(dep_vulns)

            sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            max_sev = "NONE"
            max_rank = 0
            for v in dep_vulns:
                r = sev_rank.get(v.severity.upper(), 0)
                if r > max_rank:
                    max_rank = r
                    max_sev = v.severity.upper()
            dep.max_severity = max_sev

            score, _ = risk_scorer.calculate_dependency_risk(dep, dep_vulns)
            dep.risk_score = score

        # 5. Composite project risk score & counts
        total_risk = risk_scorer.calculate_project_risk(deduped_deps, all_vulns)
        duration_ms = int((time.time() - start_time) * 1000)

        direct_count = sum(1 for d in deduped_deps if d.is_direct)
        transitive_count = len(deduped_deps) - direct_count
        crit_count = sum(1 for v in all_vulns if v.severity == "CRITICAL")
        high_count = sum(1 for v in all_vulns if v.severity == "HIGH")
        med_count = sum(1 for v in all_vulns if v.severity == "MEDIUM")
        low_count = sum(1 for v in all_vulns if v.severity == "LOW")
        lic_violation_count = sum(1 for d in deduped_deps if d.license_status == "restricted")
        unknown_lic_count = sum(1 for d in deduped_deps if d.license_status == "unknown")

        # 6. Persist scan & records in SQLite
        with get_db() as conn:
            conn.execute("""
            INSERT INTO scans (
                id, project_id, status, scan_target, total_dependencies, direct_dependencies,
                transitive_dependencies, vulnerabilities_count, critical_count, high_count,
                medium_count, low_count, license_violations_count, unknown_license_count,
                risk_score, duration_ms
            ) VALUES (?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                scan_id, p_id, str(path_obj), len(deduped_deps), direct_count,
                transitive_count, len(all_vulns), crit_count, high_count,
                med_count, low_count, lic_violation_count, unknown_lic_count,
                total_risk, duration_ms
            ))

            for dep in deduped_deps:
                dep_id = f"dep-{uuid.uuid4().hex[:12]}"
                conn.execute("""
                INSERT INTO dependencies (
                    id, scan_id, name, version, ecosystem, purl, is_direct, declared_constraint,
                    depth, source_file, declared_license, detected_license, license_category,
                    license_status, vulnerability_count, max_severity, risk_score, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    dep_id, scan_id, dep.name, dep.version, dep.ecosystem, dep.purl,
                    1 if dep.is_direct else 0, dep.declared_constraint, dep.depth,
                    dep.source_file, dep.declared_license, dep.detected_license,
                    dep.license_category, dep.license_status, dep.vulnerability_count,
                    dep.max_severity, dep.risk_score, dep.confidence
                ))

            for v in all_vulns:
                vuln_db_id = f"vuln-{uuid.uuid4().hex[:12]}"
                import json
                refs_json = json.dumps(v.references)
                conn.execute("""
                INSERT INTO vulnerabilities (
                    id, scan_id, dependency_name, installed_version, ecosystem, purl,
                    advisory_id, cve_id, ghsa_id, osv_id, summary, details, severity,
                    cvss_score, vulnerable_range, fixed_version, references_json,
                    source, status, remediation_advice
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    vuln_db_id, scan_id, v.dependency_name, v.installed_version, v.ecosystem,
                    v.purl, v.advisory_id, v.cve_id, v.ghsa_id, v.osv_id, v.summary,
                    v.details, v.severity, v.cvss_score, v.vulnerable_range, v.fixed_version,
                    refs_json, v.source, v.status, v.remediation_advice
                ))

        return ScanOut(
            id=scan_id,
            project_id=p_id,
            status="completed",
            scan_target=str(path_obj),
            total_dependencies=len(deduped_deps),
            direct_dependencies=direct_count,
            transitive_dependencies=transitive_count,
            vulnerabilities_count=len(all_vulns),
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            license_violations_count=lic_violation_count,
            unknown_license_count=unknown_lic_count,
            risk_score=total_risk,
            duration_ms=duration_ms,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S")
        )

    def _scan_directory(self, root: Path) -> List[DependencyItem]:
        results: List[DependencyItem] = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune excluded directories
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]
            for f in filenames:
                if f.lower() in ALLOWED_MANIFEST_FILENAMES:
                    file_path = Path(dirpath) / f
                    # Prevent symlink traversal outside root
                    try:
                        resolved = file_path.resolve()
                        if not str(resolved).startswith(str(root.resolve())):
                            logger.warning(f"Skipping symlink outside root: {file_path}")
                            continue
                        if file_path.stat().st_size > settings.MAX_FILE_SIZE_BYTES:
                            logger.warning(f"Skipping oversized manifest: {file_path}")
                            continue
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        parsed = parser_registry.parse_file(file_path, content)
                        results.extend(parsed)
                    except Exception as e:
                        logger.error(f"Error parsing {file_path}: {e}")
        return results

    def _scan_single_file(self, file_path: Path) -> List[DependencyItem]:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        return parser_registry.parse_file(file_path, content)

    def _scan_zip(self, zip_path: Path) -> List[DependencyItem]:
        """Safely scan in-memory ZIP bundle with ZipSlip mitigation."""
        results: List[DependencyItem] = []
        with zipfile.ZipFile(zip_path, "r") as z:
            total_uncompressed = 0
            file_count = 0
            for info in z.infolist():
                file_count += 1
                if file_count > settings.MAX_ARCHIVE_FILES:
                    raise ValueError("Archive exceeds maximum file count limit.")
                total_uncompressed += info.file_size
                if total_uncompressed > settings.MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("Archive exceeds uncompressed size decompression bomb limit.")

                # ZipSlip path traversal protection
                norm_name = os.path.normpath(info.filename)
                if norm_name.startswith("..") or os.path.isabs(norm_name):
                    continue

                leaf_name = Path(norm_name).name.lower()
                if leaf_name in ALLOWED_MANIFEST_FILENAMES:
                    content = z.read(info.filename).decode("utf-8", errors="ignore")
                    parsed = parser_registry.parse_file(Path(norm_name), content)
                    results.extend(parsed)
        return results

ingestion_scanner = IngestionScanner()
