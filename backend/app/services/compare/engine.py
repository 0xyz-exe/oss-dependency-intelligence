"""Engine for diffing two scans (baseline vs current)."""
from typing import List, Dict, Any
from backend.app.schemas.models import DependencyItem, VulnerabilityItem, ScanCompareResult

class ScanComparator:
    @staticmethod
    def compare_scans(
        baseline_scan_id: str,
        current_scan_id: str,
        base_deps: List[DependencyItem],
        curr_deps: List[DependencyItem],
        base_vulns: List[VulnerabilityItem],
        curr_vulns: List[VulnerabilityItem],
        base_risk: float,
        curr_risk: float
    ) -> ScanCompareResult:
        """Calculate deep diff between baseline and current scan."""
        base_dep_map = {d.name: d for d in base_deps}
        curr_dep_map = {d.name: d for d in curr_deps}

        added_deps = []
        removed_deps = []
        version_changes = []
        license_changes = []

        for name, curr_d in curr_dep_map.items():
            if name not in base_dep_map:
                added_deps.append({
                    "name": name,
                    "version": curr_d.version,
                    "ecosystem": curr_d.ecosystem,
                    "license": curr_d.detected_license
                })
            else:
                base_d = base_dep_map[name]
                if base_d.version != curr_d.version:
                    version_changes.append({
                        "name": name,
                        "old_version": base_d.version,
                        "new_version": curr_d.version,
                        "ecosystem": curr_d.ecosystem
                    })
                if base_d.detected_license != curr_d.detected_license:
                    license_changes.append({
                        "name": name,
                        "old_license": base_d.detected_license,
                        "new_license": curr_d.detected_license
                    })

        for name, base_d in base_dep_map.items():
            if name not in curr_dep_map:
                removed_deps.append({
                    "name": name,
                    "version": base_d.version,
                    "ecosystem": base_d.ecosystem
                })

        base_vuln_ids = {f"{v.dependency_name}::{v.advisory_id}" for v in base_vulns}
        curr_vuln_ids = {f"{v.dependency_name}::{v.advisory_id}" for v in curr_vulns}

        new_vulns = []
        for v in curr_vulns:
            key = f"{v.dependency_name}::{v.advisory_id}"
            if key not in base_vuln_ids:
                new_vulns.append({
                    "dependency": v.dependency_name,
                    "version": v.installed_version,
                    "advisory_id": v.advisory_id,
                    "severity": v.severity,
                    "summary": v.summary
                })

        resolved_vulns = []
        for v in base_vulns:
            key = f"{v.dependency_name}::{v.advisory_id}"
            if key not in curr_vuln_ids:
                resolved_vulns.append({
                    "dependency": v.dependency_name,
                    "version": v.installed_version,
                    "advisory_id": v.advisory_id,
                    "severity": v.severity,
                    "summary": v.summary
                })

        return ScanCompareResult(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            added_dependencies=added_deps,
            removed_dependencies=removed_deps,
            version_changes=version_changes,
            new_vulnerabilities=new_vulns,
            resolved_vulnerabilities=resolved_vulns,
            license_changes=license_changes,
            risk_score_delta=round(curr_risk - base_risk, 1)
        )

scan_comparator = ScanComparator()
